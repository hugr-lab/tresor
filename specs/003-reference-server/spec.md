# Spec 003: the reference server — duckdb-secrets/1 in Go, Keycloak end to end, the conformance suite

- **Status**: implemented
- **Date**: 2026-09-23
- **Author**: VGSML (with Claude)

## Summary

`server/` becomes a small but real implementation of `duckdb-secrets/1` in Go. It covers discovery,
`whoami`, the secrets resources, grants, and verification of tokens from any configured OIDC issuer.
Its secrets live in an AES-GCM-encrypted file. CI runs it next to a **Keycloak** in docker, and
tresor logs in against that pair the way a person and a service would in production: a real browser
login with PKCE, and a real client-credentials grant. The protocol page's *Conformance* section gets
its first content: sqllogictests driven against a service URL. The reference server is the first
service to pass them.

## Problem

Until now tresor was tested only against a Python fake that trusts any token it issued. Nothing
proves that tokens from a real IdP work with a real service: audience checks, JWKS, Keycloak's
role claims, service-account tokens. Spec 004 (the secret storage in tresor) also needs a service
that stores secrets. And a company writing its own service has no example to read.

## Design

### Scope

| In | Out (later specs) |
| --- | --- |
| discovery, `GET /v1/whoami` | delegation (`capabilities.delegation: false`) |
| `GET/PUT/DELETE/PATCH /v1/secrets[/{name}]`, conditional writes | dynamic secrets (`capabilities.dynamic: false`) |
| grants `GET/PUT/DELETE /v1/secrets/{name}/grants[/{id}]` | an admin UI, a database backend, HA |
| token verification (JWKS, `iss`, `aud`, expiry, algorithms), claims → principals | token introspection (RFC 7662) |
| an encrypted file store, or memory | key rotation of the store |

Production use is not a goal. Correctness and readability are.

### Layout

`server/` is its own Go module, `github.com/hugr-lab/tresor/server` (go 1.26):

- `cmd/tresor-server/` — the binary: `tresor-server -config server.yaml`.
- `internal/config` — the YAML config and its validation.
- `internal/auth` — token verification and principals.
- `internal/store` — the secrets and their persistence.
- `internal/api` — the HTTP handlers and the permission checks.

Dependencies: `github.com/coreos/go-oidc/v3` (discovery, JWKS, verification) and `gopkg.in/yaml.v3`.
The tests also use `github.com/go-jose/go-jose/v4` (already pulled in by go-oidc) to mint tokens.

### Configuration

```yaml
listen: 127.0.0.1:8443
public_url: http://127.0.0.1:8443        # discovery's `api`
tls: {cert: server.crt, key: server.key} # without it, plain http - only on a loopback listen address
store:
  path: data/secrets.enc                 # empty: memory only
  key_env: TRESOR_SERVER_KEY             # 32 bytes, base64; required with a path
issuers:
  - issuer: http://127.0.0.1:18480/realms/tresor
    audience: duckdb-secrets             # `aud` must contain it
    client_id: duckdb                    # the public client people log in with
    scopes: [openid]
    human_flows: [authorization_code, device_code]
    service_flows: [client_credentials]
    roles_claim: realm_access.roles      # dotted path to a list of strings -> role:<name>
    groups_claim: groups                 # -> group:<name>
    algorithms: [RS256, ES256]           # never none, never HS*
    service: {claim: client_id}          # what marks a client-credentials token; absent: no services
policy:
  admins: [role:secrets_admin]           # every verb on every secret, create anything
  create:                                # who may create, by name pattern (path.Match)
    - {principal: role:analysts, names: ["team_a_*"]}
    - {principal: client:etl, names: ["*"]}
```

### Principals and verification

- A request carries `Authorization: Bearer <jwt>` (the scheme is case-insensitive). The server
  reads the unverified `iss` only to pick the configured issuer. It then verifies with that
  issuer's JWKS (go-oidc: signature, `iss` compared verbatim, `exp`, the configured algorithms) and
  requires `aud` to contain the issuer's `audience`. Anything else answers `401 unauthenticated`,
  and the reason goes to the log, never the token. An issuer must be https unless it is on
  loopback, because its keys are fetched from it.
- Principals of a caller: `subject:<iss>|<sub>` always, which is its **identity and the owner of
  what it creates**. Add `role:<r>` for each role and `group:<g>` for each group claim value. A
  token is a **service's only by the issuer's `service` rule** (a claim present, optionally with a
  value). A service also gets `client:<name>` from the rule's `client_claim` (default `azp`). No
  claim is a service marker by convention: RFC 9068 puts `client_id` into every access token, a
  person's included. `client:` names are not issuer-qualified; they name what a caller holds, never
  who it is.
- Issuers are discovered lazily, bounded by a 10 s timeout on a client of their own. A failure is
  remembered for 5 s, so tokens naming an unreachable issuer do not each trigger an outbound
  request. The server starts before its IdP is up, as it does in CI.

### Permissions

A caller's verbs on a secret are the union of:
- every verb, if any of its principals is an admin;
- every verb, if it owns the secret. The owner is the creator's `subject:` or `client:` principal
  (a service owns what it creates);
- the verbs of every grant whose principal is one of the caller's.

A grant passes on at most what its grantor holds. `delegate` cannot be granted while delegation is
off.

`create` is service-level: admins, or a `policy.create` rule whose principal the caller has and
whose pattern matches the name. `GET /v1/secrets` lists the secrets the caller holds any verb on,
without material. A secret the caller holds no verb on is `404 not_found`, the same answer as for
one that does not exist.

### Secrets and conditional writes

The record: `name`, `type`, `provider`, `scope[]`, `params` (the typed values as the protocol spells
them, kept verbatim), `redact_keys`, `comment`, `owner`, `created_at`, `updated_at`, `version`
(an increasing integer, sent as a string and as the `ETag`), `grants`.

- `PUT` with `If-None-Match: *` creates only (412 when the secret exists). Without it, `PUT` creates
  (needs `create`) or replaces (needs `update`). `If-Match: "<version>"` is honoured.
- `PUT` validates the body: `type` is non-empty; `params` is an object whose values are strings or
  `{type, value}`; `redact_keys` are keys of `params`. Otherwise `422 invalid_secret`.
- `DELETE` needs `delete`. `PATCH {comment}` needs `annotate`. Grants need `grant`. A grant is
  `{principal, verbs[]}`; the verbs must be known ones, or `422`.

### The store

The whole state is one JSON document. It lives in memory; with a path, it is encrypted with
AES-256-GCM (a random nonce per write, the key from the environment) and written atomically (temp
file + rename, mode 0600) after each change. A file that does not decrypt stops the start: the
server never overwrites a store it cannot read. No material appears in logs.

### Keycloak end to end

- `server/testdata/keycloak/realm-tresor.json`, imported by `start-dev --import-realm`
  (`server/docker-compose.yml`, `quay.io/keycloak/keycloak:26.x`, `127.0.0.1:18480`). It contains:
  - realm roles `analysts`, `secrets_admin`, `etl`;
  - users `alice` (analysts) and `bob` (secrets_admin);
  - client `duckdb` (public, standard flow with PKCE S256 required, device grant, loopback
    redirects);
  - client `etl` (confidential, service account with role `etl`);
  - an audience mapper on both clients that puts `duckdb-secrets` into `aud`. A scope requested
    for it would have to exist in the realm, and Keycloak refuses unknown scopes.
- `scripts/ci/test_keycloak.sh`:
  1. Starts Keycloak and waits for the realm.
  2. Builds and starts the server with `server/testdata/keycloak/server.yaml`.
  3. Runs `test/sql/conformance/*` with the service's coordinates in the environment.
  4. Sets `BROWSER` to `test/keycloak/browser.py`, a script that fills Keycloak's login form as alice
     and follows the redirect to tresor's loopback receiver. So the browser flow runs for real:
     PKCE, `state`, Keycloak's redirect-URI checks.

Learned against Keycloak 26.4 and pinned in the realm and the tests:
- **Loopback redirects.** A redirect URI `http://127.0.0.1/*` accepts any port on a loopback
  redirect, as RFC 8252 asks.
- **The `client_id` claim.** A service account created through the admin console gets the
  `service_account` scope, which adds a `client_id` claim. An imported realm does not, so the test
  realm adds the same mapper by hand. Without that claim a service token looks like a person's.
- **Secure cookies over http.** Keycloak marks its session cookies `Secure` even over http. A real
  browser sends them to 127.0.0.1, a secure context, so the test browser does the same.

### The conformance suite

`test/sql/conformance/*.test` is driven by `TRESOR_CONFORMANCE_HOST` (plus `_INSECURE`,
`_ISSUER`, `_CLIENT_ID`, `_CLIENT_SECRET` for a service login, and optionally `_PERSON` together with a
`BROWSER` that completes the IdP's login, for a browser login). The reference server's own
expectations (its roles, its create patterns against the test realm) live apart, in
`test/sql/reference_server/`: they are not the protocol's. It checks only what the client can observe through SQL. Today that is `whoami`
for a service and for a person. The suite grows with every client spec (secrets in 004, writes in
005, …). A service is `duckdb-secrets/1` when it passes the suite. The protocol page says so and
explains how to run it.

The server's own Go tests cover the protocol at the HTTP level, where SQL cannot reach yet:
- discovery;
- verification refusals: a wrong `aud`, `iss` or algorithm, `alg: none`, an expired token, a
  wrong key;
- principals from Keycloak- and Entra-shaped claims;
- every secrets and grants route with its permission and precondition cases;
- `404` for invisible secrets;
- the store: an encrypted round trip, a wrong key refused, an atomic write.

## Enforcement & security

- The server never adds authority: every decision uses the caller's own principals. Delegation does
  not exist yet, so there is no actor.
- Fail closed: an unknown issuer, a bad signature or audience, or an unreadable store. Plain http is
  allowed only on a loopback listen address.
- Material and tokens never reach a log. The request log carries the method, the path (a secret's
  name is not secret), the status and the subject.

## Testing

- `cd server && go vet ./... && go test ./...` — on every PR (a fast job).
- `scripts/ci/test_keycloak.sh` — in the Linux build job after the attach suites, with docker. Runs
  `test/sql/reference_server/*` (the realm's roles and create patterns, two identities side by side,
  a wrong client secret) and `test/sql/conformance/*` (a service login and a browser login, each
  followed by whoami).
- `gofmt` in the lint job.

## The review's findings (applied)

An independent review, several of them reproduced:

- **People became services.** Any token with a `client_id` claim counted as a service and owned
  by `client:<azp>`. RFC 9068 tokens carry `client_id` for people too, so everyone using the public
  client owned everyone else's secrets. Now a service is recognised only by a per-issuer rule, and
  the owner is always the `subject:`.
- **`client:` names are not issuer-qualified.** They no longer confer ownership. The docs say they
  are shared across issuers.
- **`grant` alone escalated to every verb.** A grant now passes on at most what its grantor holds.
- **http issuers off loopback were accepted.** They are now refused: their keys come from there.
- **Discovery held its lock with no timeout.** It is now bounded, with a negative cache.
- **Issuers ending in `/` could never verify** (Auth0, Entra v1). They are now kept verbatim; only
  the lookup key is normalised.
- **CI lost a script's exit status behind `| tee`.** Now `pipefail`.
- **Bodies.** `null` params and trailing data are refused. `If-None-Match` with an ETag is honoured.
  A lower-case `bearer` is accepted. Unknown routes answer problem documents.
- **`test_keycloak.sh`** now uses a compose project of its own, takes its ports from the environment
  (the server config follows), checks that the server is alive, and never prints a line
  `assert_ran` could mistake for the conformance summary.
- **Protocol ambiguities, now written into the protocol page:** OR REPLACE semantics, `If-Match`,
  the answer codes, invisible names on `PUT`, grants passing on at most what the grantor holds,
  `roles` in whoami, name canonicalisation, unknown fields, and every error as a problem document.

## Alternatives considered

- **A fake IdP in Go instead of Keycloak.** The Python fake already covers the client's paths. What
  was missing is a real IdP's tokens and redirect rules.
- **SQLite for the store.** A CGO or large pure-Go dependency for one JSON document. An encrypted
  file is enough for a reference.
- **Vault/OpenBao as the backend.** It is the obvious production shape and a good follow-up example,
  but too heavy for a readable reference.

## Follow-ups

- Delegation and dynamic secrets in the server, alongside the client specs.
- A second reference backend (OpenBao) as an example.
- Entra ID live validation (the claims shape is unit-tested).
