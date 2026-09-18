# Spec 001: tresor — attach a secrets service, one OIDC login, role-based secrets

- **Status**: accepted (scaffold implemented: the `tresor` ATTACH type is registered and loads the
  extension by prefix; the attach itself is specs/002)
- **Date**: 2026-09-18
- **Author**: VGSML

## Summary

tresor is the DuckDB client of an **external secrets service**. A person (CLI/UI) or a service
(a process running DuckDB) logs in once through **any OIDC provider**, and the secrets the caller's
role may use take part in DuckDB's own secret lookup — `ATTACH … (SECRET x)`, `FROM 's3://…'`.
Secrets are created through DuckDB too (`CREATE PERSISTENT SECRET … IN corp`), and the service's
policy — who may use, create, share or delegate what — is managed with SQL. The service is anything
that implements the open protocol **`duckdb-secrets/1`**; how it stores secrets and models policy is
its own business.

## Problem

In a company, DuckDB users reach databases, object stores and APIs with credentials that today live
in environment variables, local secret files or chat messages. There is no single login, no central
revocation, no record of who used which credential, and no way to let a server act for a user
without handing either of them more than they need. DuckDB has a solid secret manager — types,
scope matching, pluggable storages — but no way to source secrets from a corporate service by the
user's identity.

## Design

### The ATTACH is the entry point

`ATTACH 'tresor:<host>[:port][/base]' AS corp` (or `ATTACH '<host>' AS corp (TYPE tresor)`, or with a
local secret of type `tresor` holding service credentials). Verified on the 2.0 line:

- **The prefix loads the extension.** An unknown ATTACH type resolves to an extension of the same
  name, which duckdb loads if installed — even with autoloading off
  (`DatabaseManager::GetDatabaseType`). The extension name *is* the prefix, so the ATTACH is the only
  statement a user writes. Proven by `test/sql/attach_loads_extension.test` and
  `scripts/ci/smoke_load.sh`.
- **The path has no scheme.** Before it looks at the type, ATTACH treats an `http(s)://` path as a
  remote database file: it requires httpfs and forces `READ_ONLY`
  (`DatabaseManager::AttachDatabase`, `FileSystem::IsRemoteFile`). So the service is named by
  host/port/base with https implied — the shape quack uses (`quack:host:port`). Pinned by a test.

### The attached catalog is three things

1. **A secret storage** registered under the catalog's name (`SecretManager::LoadSecretStorage`):
   its secrets join every lookup; `CREATE PERSISTENT SECRET … IN corp` stores into the service
   (`StoreSecret`, with duckdb's `OnCreateConflict` mapped to HTTP preconditions), `DROP … FROM corp`
   deletes there; `SET default_secret_storage = 'corp'` makes it the default. There is no API to
   remove a storage, so DETACH deactivates it and a re-ATTACH of the name reactivates it.
2. **A catalog of table functions** — `corp.secrets()`, `corp.whoami()`, `corp.grants(…)`,
   `corp.delegations(…)` and the management calls (`annotate_secret`, `grant_secret`,
   `revoke_secret`, `add_delegation`, …). duckdb resolves `corp.f()` inside an attached catalog
   (`Binder::Bind(TableFunctionRef)`).
3. **A login.** Discovery (`/.well-known/duckdb-secrets`, then the issuer's
   `openid-configuration`), then: people — authorization code + PKCE with a loopback redirect, or a
   device code; services — client credentials, `private_key_jwt`, federated assertions (Kubernetes,
   Azure workload identity). The login is direct with the identity provider, never through the
   secrets service: other servers need IdP tokens too, and one login mints them per audience.

### Lookup and material

The storage keeps the list of descriptors the caller may see (no material) and answers
`LookupSecret(path, type)` from it; material is fetched **on a match** and cached until it expires.
*Dynamic* secrets carry an expiry; S3/GCS ones are refreshed through httpfs's own `REFRESH auto`,
which re-runs the secret's provider with the same type/provider/scope/storage — so tresor's
provider is called back when a credential runs out (`TryRefreshS3Secret`).

### Permissions, grants, delegation

The service decides verbs — `create` (service-wide, possibly by name pattern), `use`, `update`,
`delete`, `annotate`, `grant`, `delegate`. Grants are part of protocol v1; delegation is an
optional capability, and a secret is **not delegated** unless it has a rule. A rule names actors
(servers), subjects (users/roles), a mode — `user` (a personal credential is issued) or `shared` (the
server uses a shared secret only for that user, who need not hold `use`: *use without seeing*) — and
narrowing (operations, scope, TTL). A server acting for a user presents a delegation grant; the
service checks the user's rights, the rule, and that the actor may act for users at all. The
normative text is the protocol page, `website/docs/protocol.md`.

### Server side (acl) — outside this repository

On a duckdb-acl node, acl parses and checks secret management under its own role policy
(`ACL GRANT SECRET` / `ACL DELEGATE SECRET` compiled into tresor's functions), and tresor executes
with the **user's** delegation grant — two gates, both must pass; a server never adds its own
authority. The per-connection state acl publishes (`acl_connection`) and the file gate +
`session://` scratch are acl's specs.

### Audit

tresor publishes its own audit hook — a contract in `duckdb-ext-common/contracts/tresor_audit.hpp`
on the `hooks/` base (stamped registry in the object cache, sinks, bounded queue) — independent of
acl; acl-otel subscribes to it as a second producer. Events never carry material, tokens, session
handles or grant ids. DuckDB's native logging gets a structured `tresor` log type for diagnostics.

### Pins

The 2.0 line at **duckdb-acl's duckdb commit** (`v2.0-cyanoptera`), extension-ci-tools at acl's
commit (`main`), duckdb-ext-common at `main` until its first tag. On a server tresor, acl and
acl-otel load into one DuckDB, and loadable extensions must match the host exactly — bump together.

## Enforcement & security

- The client never writes material to disk, never emits material/tokens/handles in logs or events,
  and sends an IdP token only to the audience it was issued for.
- On a person's machine, `use` of a static secret means seeing it — protection lives in the service:
  personal dynamic credentials for people, `shared` delegation for use-without-seeing.
- On a server: `allow_unredacted_secrets = false`, `lock_configuration = true`, no `CREATE SECRET`
  for principals.

## Testing

- `test/sql/tresor.test` — the version function; both ATTACH spellings reach tresor's attach; a
  schemed path requires httpfs (why the path has no scheme).
- `test/sql/attach_loads_extension.test` — installed into an isolated extension directory, the
  extension is loaded by `ATTACH 'tresor:…'` alone, with autoloading off.
- `scripts/ci/smoke_load.sh` — the same, from a CLI outside the tree, plus an explicit LOAD.
- Next (specs/002+): a reference server + conformance suite; a Keycloak container in CI.

## Alternatives considered

- **A bridge from environment variables / local secret files** — no single login, no revocation, no
  audit, no delegation.
- **Login through the secrets service** (the service as a confidential client holding refresh
  tokens) — turns it into a token vending machine for the whole environment; other servers need
  IdP tokens anyway.
- **An `init()` function instead of ATTACH** — two statements instead of one, and no implicit load.
- **A URL in the ATTACH path** — requires httpfs and forces read-only (above).
- **boilstream** (community) — remote secrets with an email/password PAKE login; no corporate SSO,
  no roles from the IdP.
- **DuckDB's native logging for audit** — one active log storage per instance and user-switchable;
  kept for diagnostics only.

## Follow-ups

- specs/002 — attach, discovery, login (people + services), `corp.whoami()`.
- specs/003 — the storage: list, lookup, material cache; `corp.secrets()`.
- specs/004 — writes, annotate, grants.
- specs/005 — dynamic secrets and the `REFRESH auto` provider.
- specs/006 — delegation (grant exchange, rules).
- duckdb-ext-common — `hooks/` base and `contracts/tresor_audit.hpp`; the OIDC core additions.
- The reference server (`server/`, Go) and the conformance suite.
