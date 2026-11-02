# Spec 045: the architecture as of 0.1 - what tresor is after specs 002-044

- **Status**: accepted
- **Date**: 2026-10-29
- **Author**: hugr lab
- **Asked by**: a design review (2026-10-29): spec 001, which every reader is sent to first, still describes
  users who create and share secrets and delegation rules (removed by specs/009), and pins that have moved
- **Supersedes**: spec 001 (its design is kept where this spec repeats it; where they differ, this one holds)

## Summary

The architecture of tresor 0.1 (DuckDB 2.0.0, protocol `duckdb-secrets/1` version 1), in one place, so that a
reader no longer has to replay specs 002-044 over spec 001. It decides nothing new: every point names the spec
that decided it. The protocol's normative text stays `website/docs/protocol.md`; the SQL surface is
`website/docs/reference.md`.

## Problem

Spec 001 was written before any implementation (2026-09-18). Since then:
- specs/009 replaced its permission model: only administrators create, change and grant; `use` is granted to
  roles and groups only; delegation has no rules and no `user`/`shared` modes; a server under a grant uses its
  own grants. 001's Summary ("who may use, create, share or delegate what") and its *Permissions, grants,
  delegation* section describe the removed model;
- its *Pins* name `v2.0-cyanoptera` and duckdb-ext-common at `main`; the pins are DuckDB `v2.0.0` and
  duckdb-ext-common `v0.15.0` (specs/038, CLAUDE.md);
- its *Follow-ups* are numbered one off from the specs that did the work, and its *Testing* says "Next";
- it knows nothing of variables (018, 037), generated parameters (010, 029), the keychain (012), logins from
  any client (025), wasm (020, 042-044), embedding (024), the audit's contract (011) or `enable_external_access`
  (036).

## Design

### The entry point (001, unchanged)

`ATTACH 'tresor:<host>[:port][/base]' AS corp`. The prefix loads the installed extension, even with
autoloading off; the path has no scheme, since an `https://` path makes DuckDB require httpfs and attach
read-only before it looks at the type. Several services can be attached at once, each its own storage,
catalog and login.

### The attached catalog

1. **A secret storage** named after the catalog (specs/004, 005). Offsets 40-99, unique per instance: on a
   tie of scope length DuckDB's own storages (temporary, local file) win. `CREATE PERSISTENT SECRET … IN corp`
   and `DROP … FROM corp` write to the service with HTTP preconditions; DETACH deactivates the storage (DuckDB
   cannot remove one) and a re-ATTACH of the name reactivates it.
2. **Functions** in the catalog: the view (`whoami`, `secrets`, `variables`, `variable`), an administrator's
   management (`grants`, `grant_secret`, `revoke_secret`, `annotate_secret` and the variables' counterparts,
   018), and `act_for_sessions` (015). Functions of the extension itself: `tresor_login`, `tresor_logoff`
   (025), `tresor_web_login` (020), `tresor_web_token` (043), `tresor_secret_param`, `tresor_version`.
3. **A login** that every call to the service carries (below).

### Logins (002, 012, 013, 025, 026, 043)

- Discovery: `{base}/.well-known/duckdb-secrets`, then the issuer's `openid-configuration`. With several
  issuers the user names one (`ISSUER`); list order never chooses an identity.
- Always directly with the identity provider, never through the service.
- **A person**: authorization code + PKCE on a loopback redirect, or a device code (with PKCE where the IdP
  advertises it, 040); from any client through `tresor_login`, completed in the background (025). The refresh
  token is kept in the OS credential store, keyed per service, issuer and client (012) - the one thing tresor
  ever keeps.
- **A service**: a `tresor` secret - `client_credentials` (a secret or `private_key_jwt`), `federated`
  (a file, GitHub Actions, Azure managed identity as the assertion), `managed_identity`, or a `token` it holds
  (013, 026). Never the keychain.
- **A web page**: the page logs in and hands over its refresh token (`tresor_web_login`) or its access token
  (`tresor_web_token`), in memory only (020, 043).

### Lookup and material (004, 006, 010, 029, 032)

- The descriptor list (no material) is cached for 30 s, refreshed single-flight; DuckDB's own scope rule
  picks the match. Material is fetched only for the match.
- Static material is cached for 300 s; dynamic material until shortly before its `expires_at`. Material
  fetched for one caller is never served to another - not across users, not between a node's own work and a
  session's.
- Fail closed only where the service would decide: a covered path fails at the fetch, naming service and
  secret; other paths and local secrets keep working.
- Any parameter of any type may be generated per caller (029); s3/gcs/r2/aws dynamic secrets renew through
  httpfs's `REFRESH auto` and tresor's provider (006). A type with its own secret class gets that class (032).

### Permissions (009, the protocol's *Permissions*)

Administrators (the service's configuration) create, update, delete, annotate and grant. `use` comes only
from a grant to a `role:` or `group:`; neither an administrative role nor creating a secret implies it. A
user's own credentials stay in their own DuckDB (`CREATE SECRET`). So only an administrator can put a secret
on anyone's lookup path.

### Variables (018, 037)

Optional (`capabilities.variables`): named strings, read by name, never part of a lookup. Same names,
permissions, writes and errors as secrets; a `sensitive` value is handled as material; a value may carry an
`expires_at`.

### Acting for users (008, 009, 010, 015)

On a duckdb-acl node, `ACT_FOR_SESSIONS` (or `act_for_sessions()` later, 015): for each acl session tresor
exchanges the session's token at the IdP (RFC 8693, or Entra's On-Behalf-Of) for one meant for the service,
trades it for a delegation grant, calls with the node's token and `Delegation: <id>`, and revokes the grant
when the session ends. Under a grant `use` is the node's own; management passes only for a user who is an
administrator and only as the service's actor policy allows; caller-dependent material is minted for the
user. acl's own role policy (`ACL GRANT SECRET`) is a second gate: both must pass, and a node never adds
its own authority.

### Audit (011)

tresor's own hook, `duckdb-ext-common/contracts/tresor_audit.hpp` (`TRSA`, stamped; a layout change bumps
it), independent of acl; acl-otel subscribes. DuckDB's log gets the same events as type `tresor`
(`tresor_audit_level`). Events never carry material, tokens, session handles or grant ids. A `traceparent`
is sent to the service when the statement has one.

### Transport and platforms (020, 030, 036, 042, 044)

The OIDC core of duckdb-ext-common is the built-in HTTP client (OpenSSL, DuckDB's `ca_cert_file` beside the
system's roots); `tresor_http_client = 'duckdb'` uses DuckDB's HTTP client instead, the only one in wasm. Both
obey `enable_external_access` and `allowed_directories`. Linux, macOS, Windows (x64, arm64), wasm (`wasm_eh`,
`wasm_threads`). tresor can be built into another extension (`tresor_sources.cmake`, `LoadTresorCore`, 024).

### Pins

DuckDB `v2.0.0` (d54cbbe) at duckdb-acl's commit; extension-ci-tools at acl's commit; duckdb-ext-common
`v0.15.0`. tresor, acl and acl-otel load into one DuckDB on a server and bump together (CLAUDE.md has the
table).

## Enforcement & security

Unchanged from 001 and the specs above, collected in `website/docs/security.md`:
- No material on disk, in logs or in events; tokens go only to their audience; the person's refresh token in
  the OS credential store is the single exception (012).
- On a person's machine `use` of a static secret means seeing it; use-without-seeing is a server's, under a
  grant.
- On a server: `allow_unredacted_secrets = false`, `lock_configuration = true`, no `CREATE SECRET` for
  principals.

## Testing

None of its own: this spec describes, it does not change. Each point is proven by the spec it names.

## Alternatives considered

- **Rewriting spec 001 in place** - the specs process supersedes, so a decision's history stays readable.
- **Superseding 001 section by section with pointers only** - a reader would still assemble the design from
  a dozen specs.

## Follow-ups

Open questions from the same design review, not decided here; each is a spec of its own if taken up:
- the client learns the token's audience from the discovery of the service it attaches: document that the
  IdP must restrict the `duckdb` public client to the service's audience, and consider trusted issuers on the
  client;
- the protocol's `If-Match` row is normative, but no client sends it and the conformance suite does not check
  it;
- the protocol puts no bound on caching static material (tresor: 300 s), which is also the revocation delay;
- `401 unauthenticated` covers both an expired token and a grant presented by another actor, which a client
  refreshes and retries for nothing;
- a delegation grant's id travels in the path of its `DELETE`.
