# Spec 002: attach — discovery, one OIDC login (people and services), `corp.whoami()`

- **Status**: implemented
- **Date**: 2026-09-23
- **Author**: VGSML (with Claude)
- **Other side**: duckdb-ext-common `specs/003-oidc-auth-code` (the browser flow in the OIDC core, the
  TLS gate fix, the transport for service calls)

## Summary

`ATTACH 'tresor:<host>' AS corp` becomes real. It discovers the service, logs in **directly with the
identity provider** the service names, and checks the login with the service's `whoami`. The result
is an attached catalog `corp` whose first function is `corp.whoami()`. People log in through a
browser (authorization code + PKCE on a loopback redirect) or a device code. Services log in with
client credentials, or with a token they already hold, taken from a local secret of type `tresor`.
Tokens live only in the process's memory, and `DETACH corp` logs out. Secrets, lookup and writes are
specs 003–004. This spec is the door they go through.

## Problem

The scaffold registers the `tresor` ATTACH type, and its attach throws "not implemented". Nothing can
reach a service yet, and every later spec (storage, writes, dynamic secrets, delegation) needs an
authenticated session to a discovered service.

## Design

### SQL surface

```sql
-- a person: the service's discovery names the IdP; a browser opens (or a device code is shown)
ATTACH 'tresor:secrets.corp' AS corp;
ATTACH 'tresor:secrets.corp' AS corp (LOGIN 'device');          -- 'auto' (default) | 'browser' | 'device'
ATTACH 'tresor:secrets.corp:8443/api' AS corp (ISSUER 'https://idp.corp/realms/main');  -- pick among several

-- a service: a local secret of type tresor, found by the ATTACH path through the secret's SCOPE
CREATE SECRET corp_login (TYPE tresor, SCOPE 'tresor:secrets.corp',
                          FLOW 'client_credentials', CLIENT_ID 'etl', CLIENT_SECRET '…',
                          ISSUER 'https://idp.corp/realms/main');
ATTACH 'tresor:secrets.corp' AS corp;
ATTACH 'secrets.corp' AS corp (TYPE tresor, SECRET corp_login);  -- or named explicitly
CREATE SECRET (TYPE tresor, SCOPE 'tresor:secrets.corp', FLOW 'token', TOKEN '…');  -- a token already held

-- development against a local service: plain http, loopback hosts only, explicitly
ATTACH 'tresor:127.0.0.1:8080' AS dev (INSECURE_HTTP true);

FROM corp.whoami();
DETACH corp;                                                      -- logout: tokens dropped
```

ATTACH options: `LOGIN`, `ISSUER`, `SECRET`, `INSECURE_HTTP`, `LOGIN_TIMEOUT` (seconds, default 300).
An unknown option is an error, not ignored. The path keeps the shape of spec 001:
`[tresor:]host[:port][/base]`, no scheme (a scheme is refused, and pinned by a test).

### Discovery

1. `GET https://<host>[:port][/base]/.well-known/duckdb-secrets` with no authentication. `protocol`
   must be `duckdb-secrets/1`, and `api` must be an absolute URL. Under `INSECURE_HTTP` it may be
   `http://` only to a loopback host. Otherwise it must be `https://`.
2. The issuer is the one named by `ISSUER` (it must be listed), or the only one listed. When the
   service lists several and none is named, ATTACH fails and lists them. Silently taking the first is
   a guess about identity.
3. `GET <issuer>/.well-known/openid-configuration` through the OIDC core (RFC 8414 issuer check,
   downgrade check).

### Login

| Who | Flow | From | Notes |
| --- | --- | --- | --- |
| person | `browser`: authorization code + PKCE (S256), redirect to `http://127.0.0.1:<ephemeral>/callback` | discovery `client_id` (public), `scopes` | the URL is printed to stderr and a browser is opened |
| person | `device`: RFC 8628 | same | the verification URI and user code are printed to stderr |
| service | `client_credentials` | secret `CLIENT_ID`, `CLIENT_SECRET`, optional `OAUTH_SCOPE` | re-minted when the token runs out |
| service | `token` | secret `TOKEN` | no renewal: when it expires, calls fail with a clear error |

- **`LOGIN 'auto'`** picks `browser` when the issuer advertises an `authorization_endpoint` and a
  browser can be opened: always on macOS and Windows, and on Linux when `DISPLAY` or
  `WAYLAND_DISPLAY` is set. Otherwise it picks `device`. The issuer must also allow the flow chosen
  (`human_flows` in discovery, when present).
- **Opening the browser**: if the environment variable `BROWSER` is set (the common convention), that
  program is run with the URL as its last argument. Otherwise `open` (macOS), `xdg-open` (Linux) or
  `ShellExecuteW` (Windows). The URL is passed as one argv element and never through a shell. On
  Windows only an `http(s)://` URL is ever handed over. The child's stdin/stdout/stderr go to
  `/dev/null`, so its output never mixes into the query's. The child is not waited for. A browser
  that fails to start is not an error: the printed URL still works. On macOS over SSH (`SSH_CONNECTION`
  / `SSH_TTY`), `auto` picks the device flow.
- **Blocking and cancelling**: the login runs inside ATTACH. The wait honours the connection's
  interrupt (Ctrl-C) and `LOGIN_TIMEOUT` (for the device flow, also the IdP's `expires_in`).
- **Scopes**: people request the discovery `scopes`. Services request `OAUTH_SCOPE` when it is set,
  otherwise the discovery `scopes` without `openid` and `offline_access`, which a client-credentials
  grant has no use for. `audience` in discovery is informational for the client. The service checks
  `aud`, and getting the audience right is the IdP configuration's job (client scope / app ID URI).
- **Secret lookup**: without `SECRET` and without `LOGIN`, ATTACH looks for a `tresor` secret
  covering the path `tresor:<host>[:port][/base]`, in whichever spelling the ATTACH used. If one
  covers it, this is a service login; otherwise a person logs in.
  - **At a host boundary.** A SCOPE covers the path itself, a path under it (`/`), and, when the
    scope names no port, the same host on any port (`:`). It is compared case-insensitively. It is
    never a plain string prefix: `tresor:secrets.corp` must not cover `tresor:secrets.corp.attacker.net`.
  - **The most specific scope wins.** Two secrets that cover the path equally are an error that asks
    for `SECRET`.
  - **`LOGIN` given** means a person asks to log in as themselves, so no secret is looked up.
    `LOGIN` together with `SECRET` is refused.
- **A service's credential is bound to its IdP**: a `client_credentials` secret must name its
  `ISSUER`. The service's discovery must list that issuer, but it never chooses where a client secret
  is sent. An ATTACH `ISSUER` that differs from the secret's is refused. A `token` secret involves no
  IdP: the held token goes to the service alone, and its `SCOPE` binds it to that service.
- **A taken name is refused before the login.** duckdb checks the name only after the storage's
  attach, so without this a person would finish a browser login and then read "already exists".

### After the login: the session

- The tokens (access, refresh, expiry) live in memory, in the catalog's session object. They are
  never on disk, in a log or in an error message. `DETACH` drops them. For `client_credentials`
  the session keeps a copy of `CLIENT_SECRET` in memory, so it can re-mint; `DETACH` drops that too.
  The duckdb secret it came from is the user's (a `PERSISTENT` one is on disk, as for any duckdb
  secret).
- Before each service call, a token with less than 60 s left (or less than half its life, for
  tokens that live 2 minutes or less) is renewed: with the refresh token
  (people), by re-minting (`client_credentials`), or not at all (`token`). A `401` from the service
  forces one renewal and one retry (protocol, *Errors*). A refresh answered with `invalid_grant` means
  the login is over. That call and every later one fail with "log in again: DETACH and ATTACH". A new
  browser window never opens in the middle of a query.
- One lock guards the session, held across the network call so that renewals do not race. A slow
  service or IdP therefore holds the other connections' calls for up to the transport's timeout.
- ATTACH ends with `GET /v1/whoami`. A token the service refuses fails the ATTACH, closed.
- Keeping the refresh token across processes (OS keychain) is a later spec (design §13).

### The attached catalog

`TresorCatalog` is a `DuckCatalog` on in-memory storage (the attach sets the path to `:memory:`),
switched to a read-only database after its initialization (`AttachedDatabase::SetReadOnlyDatabase`).
Tables, views and inserts in `corp` are refused by duckdb's own read-only check. `GetCatalogType()`
is `tresor`. Its schema `main` carries the catalog's table functions, bound to the session through
`TableFunctionInfo`, which duckdb resolves inside an attached catalog (spec 001). This spec adds
`whoami`:

| column | type | from |
| --- | --- | --- |
| `service` | VARCHAR | the `api` URL |
| `issuer` | VARCHAR | whoami |
| `subject` | VARCHAR | whoami |
| `roles` | VARCHAR[] | whoami |
| `actor` | VARCHAR | whoami (NULL unless delegated) |
| `expires_at` | TIMESTAMPTZ | whoami |
| `can_create` | VARCHAR[] | `permissions.create`: `true` → `['*']`, `false` → `[]`, a list as is |
| `login` | VARCHAR | the flow used (`browser`, `device`, `client_credentials`, `token`) |

`Catalog::OnDetach` clears the session. The secret storage registration is spec 003's.

### The `tresor` secret type

Type `tresor`, provider `config`. Parameters: `FLOW` (`client_credentials` | `token`); for
`client_credentials`, `CLIENT_ID`, `CLIENT_SECRET` and `ISSUER` (all required) and an optional
`OAUTH_SCOPE`; for `token`, `TOKEN`. `CLIENT_SECRET` and `TOKEN` are redacted. **`SCOPE` is required**
and has the shape `tresor:<host>[:port][/base]`, because an unscoped secret would match every lookup
in duckdb. The parameters are validated at CREATE: a flow needs its own parameters and refuses the
others'.
`private_key_jwt`, federated assertions and Azure identities are follow-ups (duckdb-ext-common's
next oidc spec).

### Transport and TLS

All HTTP goes through the OIDC core: its flows, plus the generic request its spec 003 adds for the
service API (`Authorization: Bearer`). tresor links **OpenSSL from vcpkg** (its first dependency,
wired as in duckdb-acl) and compiles the core with `DUCKDB_EXT_COMMON_OIDC_TLS=1` in namespace
`duckdb::tresor::oidc`. The certificate is verified against the OS trust store, and no option turns
that off.

### Protocol page changes (`website/docs/protocol.md`)

- *Conventions*: a client may speak plain http to a **loopback** service when the user explicitly
  asks for it (development and tests). Never otherwise.
- *Discovery*: with several `issuers`, the client needs the user to name one. `human_flows` /
  `service_flows` restrict what a client attempts. `audience` is what the service checks, and
  obtaining a token for it is IdP configuration.
- *Discovery*: `api` is absolute and at least as secure as the discovery request. The resource paths
  (`/v1/...`) are appended to it. The page's example used to put `/v1` into `api` as well, which
  made the resource URLs ambiguous.

## Enforcement & security

- Login is directly with the IdP. The service only ever sees access tokens issued for it.
- Fail closed: an unverifiable certificate, an issuer mismatch, a downgraded endpoint, a refused
  whoami, an unknown option or an ambiguous issuer all fail the ATTACH, and no catalog is left
  behind.
- Tokens are in memory only and never printed. Errors carry the IdP's or service's error codes,
  never a token. The browser URL printed to stderr carries only the public `client_id`, the PKCE
  challenge and the `state`, which is how the flow is designed.
- The loopback receiver binds `127.0.0.1` only and accepts only its own `state` (duckdb-ext-common
  spec 003).
- `INSECURE_HTTP` refuses any host other than `127.0.0.1`, `::1` and `localhost`.
- `corp` is read-only as a database. Management goes through the catalog's functions (later specs),
  whose authority is the service's decision.

## Testing

- **A fake service + IdP** (`test/fake/fake_service.py`, Python stdlib, plain http on loopback).
  It serves discovery, `whoami` (a map from token to identity), the IdP's discovery, `/authorize`
  (auto-approve → 302 to the redirect with code and state, PKCE recorded), `/token`
  (`authorization_code` with PKCE check, `refresh_token`, `client_credentials`, the device code) and
  `/device`. Its behaviour is chosen by the realm, which is the base path of the ATTACH: `multi`,
  `wrong`, `expiring`, `revoking`, `noflows`.
- **`scripts/ci/test_attach.sh`** starts the fake on a free port, exports `TRESOR_TEST_PORT`, sets
  `BROWSER` to a script that plays the browser (`curl` following the 302 to the loopback), and runs
  `test/sql/attach/*.test` with `--skip-error-messages ''`. By default the runner turns an error that
  mentions "HTTP" into a *skip* (a network-flake guard), and here those errors are what the tests
  assert. The tests `require-env TRESOR_TEST_PORT`, so the plain unittest run skips them. CI runs the
  script on Linux and macOS, and `assert_ran.sh` forbids a skip there.
- The service's `whoami` and the fake's realms (`expiring`: a token as first issued is accepted
  twice, then 401 until renewed; `revoking`: its IdP refuses every refresh) are how a test steers the
  renewal paths, because a sqllogictest can only choose what it attaches.
- `test/sql/attach_auto/auto_device.test`: `LOGIN 'auto'` with no way to open a browser takes the
  device flow. It runs on Linux CI in a process without `BROWSER` or a display.
- The review's findings, pinned: a scope that is a prefix but not a host does not cover; a portless
  scope covers any port; `LOGIN` bypasses a covering secret; `LOGIN` + `SECRET` is refused; a
  secret's issuer cannot be re-aimed; equally specific secrets are an error; a taken name is refused
  before the login; a client_credentials re-mint after a 401; a login ended by `invalid_grant` stays
  ended (no empty bearer is ever sent); empty flow lists attempt nothing; unscoped and misshaped
  secrets are refused at CREATE; `@` in the name is refused.
- Cases (`test/sql/attach/*`, `test/sql/attach_options.test`): the browser login end to end; the
  device login; client_credentials through a scope-matched secret (both ATTACH spellings) and a
  named `SECRET`; the `token` flow; the `whoami` columns; renewal after a 401; refresh refused →
  "log in again"; a wrong client secret; a token the service refuses; an unknown secret name; an
  ambiguous issuer; an unlisted and a listed `ISSUER`; a wrong protocol string; a non-service (404);
  https to the http fake fails; `INSECURE_HTTP` to a non-loopback host refused; `corp` refuses
  `CREATE TABLE`; `DETACH` then `whoami` fails; the secret type's validation and redaction
  (`duckdb_secrets()` never shows `CLIENT_SECRET`); bad `LOGIN` / `LOGIN_TIMEOUT` values and an
  unknown option.
- The existing gate tests stay: the prefix loads the extension, and a schemed path requires httpfs.
- Real IdPs (Keycloak in docker, Entra) arrive with the reference server (next).

## Alternatives considered

- **A custom `Catalog` from scratch** instead of an in-memory `DuckCatalog`: about 30 pure virtuals
  to stub for a catalog that only holds functions. The `DuckCatalog` + read-only switch reuses
  duckdb's own function lookup and read-only refusal.
- **A setting for the browser command**: SQL could then choose a program to execute. `BROWSER` is
  set by the process owner, not by SQL.
- **Taking the first issuer silently**: an identity decision made by list order.
- **Tokens in a file / keychain now**: owner's decision — keychain later, on all three platforms,
  as its own spec.

## The review's findings (applied)

An independent review, with the defects reproduced against the fake:

- **An unscoped `tresor` secret covered every ATTACH, and scopes matched as plain string
  prefixes.** duckdb's lookup scores an empty scope as "matches all", so `tresor:secrets.corp` also
  covered `tresor:secrets.corp.attacker.net`. A client secret could go to another host's IdP, or a
  held token to another host's API. Fixed: SCOPE is required with the `tresor:` shape, and tresor
  matches scopes itself, at host boundaries.
- **The service's discovery chose which IdP received a service's client secret.** Fixed:
  `client_credentials` secrets carry their `ISSUER`.
- **An explicit `LOGIN` was ignored when a secret covered the path.** Now `LOGIN` means a person.
- **After `invalid_grant`, the next call sent an empty bearer token** and failed with a transport
  error. Now the login stays over and every call says so.
- **Re-attaching a taken name ran a full login first.** Now it is refused up front.
- **Also fixed:** the browser child's output went to the query's stdout (now `/dev/null`); `BROWSER`
  with arguments was taken whole on Windows (now split); present-but-empty flow lists counted as
  absent; host names could carry `@`/`?`/`#`; a `token` login fetched an IdP document it never uses;
  whoami's JSON leaked if parsing threw (RAII now); renewal of very short-lived tokens; the SSH case
  on macOS; CI's vcpkg is pinned to the distribution build's commit.

## Follow-ups

- specs/003 — the secret storage, `corp.secrets()`.
- The reference server (`server/`, Go) + Keycloak in CI + the conformance suite.
- duckdb-ext-common: `private_key_jwt`, federated assertions, Azure identities → the `tresor` secret's
  further flows.
- OS keychain for the refresh token (design §13).
- `audience` as an authorization parameter for IdPs that need it (Auth0).
