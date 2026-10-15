# Spec 029: dynamic parameters - any type, any parameter generated per caller

- **Status**: implemented
- **Date**: 2026-10-15
- **Author**: hugr lab
- **Asked by**: the owner, with tresor-server (decided 2026-10-15; tresor-server implements the same syntax)

## Summary

Dynamic secrets become abstract. A service may generate **any parameter of any secret type** on each
read, instead of the reference server's one mechanism, `provider: token_exchange` with a fixed
type-to-parameter map (`http.bearer_token`, `quack.token`, spec 010). The protocol says what a client
receives; how a service writes a generated parameter is its own. The reference server and tresor-server
share one syntax: a parameter's whole value `mint+<kind>://…`.

```json
{"type": "mssql", "provider": "access_token", "scope": ["mssql://sql.corp.example"],
 "params": {"host": "sql.corp.example",
            "access_token": "mint+exchange://https://database.windows.net/?scope=user_impersonation",
            "user": "mint+claim://upn"}}
```

## Problem

- A token for the caller fitted two types only. An `mssql` secret with Entra's `access_token`, an
  `http` secret whose header carries the caller's tenant, a `postgres` user named after the caller:
  none could be served.
- The secret's `provider` was the service's mechanism (`token_exchange`), not the provider the DuckDB
  extension that consumes the secret knows.

## Design

### The protocol (`website/docs/protocol.md`, "Dynamic secrets")

- A service MAY generate a parameter on each read: its whole value, or a part of a string, including
  strings inside `MAP`, `STRUCT` and `LIST` values. The secret is then `dynamic`, with `expires_at`
  (the earliest expiry of what was generated).
- The descriptor's `provider` is the **consumer's** (`config`, `access_token`, …), never the service's
  mechanism.
- The client receives **resolved values only**. The generator syntax is **not normative**, as a
  variable's references (`ref+…`) are not: it is the services'.
- Every generated key is listed in `redact_keys`.
- Caller-dependent material is made for the **effective user**: the direct caller, or under a
  delegation grant the grant's user, never the server (already a rule, cross-referenced from
  Delegation).
- Failures: `403 mint_refused` (lasting), `503` (outage), never an empty value.
- `capabilities.dynamic` is described (informational); the reference server now says `true`.

### The services' shared syntax (`website/docs/reference-server.md`, "Generated parameters")

A parameter's **whole** `VARCHAR` value (a JSON string):

| Value | Generates | Reference server |
| --- | --- | --- |
| `mint+exchange://<audience>[?scope=<scope>]` | a token for the effective user at the IdP (RFC 8693; spec 010's exchange) | yes |
| `mint+claim://<claim>` | the text of a top-level claim of the caller's verified token, never the token | yes |
| `mint+login://…` | tresor-server's | no |
| `mint+rule://…` | tresor-server's | no |

- `exchange`: the audience is everything up to the first `?`, percent-decoded; the query is
  `scope=<scope>` only, form-encoded.
- `claim`: a string as it is, a number or boolean as its JSON text; missing, empty, a list or an object
  is `403 mint_refused`. Expiry: the caller token's (under a grant: the grant's).
- **The escape (whole values).** Exactly one `+` after `mint` is a generator; a value beginning
  `mint++` is a literal with one `+` dropped (`mint++x` → `mint+x`, `mint+++x` → `mint++x`). The
  mapping is a bijection: a literal `L` beginning `mint+` is stored as `mint+` + `+` + `L[5:]`. The
  prefix is exact and lowercase (`MINT+x` is a literal as is). This doubles a character, as
  tresor-server's `$${` does for a literal `${` in interpolated strings.
- **Interpolation** (`${…}` inside a string, inside nested values too) is tresor-server's; the
  reference server implements the whole-value forms only and serves a `${…}` as written. A typed
  value (`{"type": …, "value": …}`) is always a literal in the reference server.
- A malformed `mint+` value or an unknown kind is refused at PUT (`422 invalid_secret`), naming the
  parameter and never its value; so is an exchange for the service's own audience.

### The reference server (`server/internal/api/generated.go`)

- Only administrators write generators, as any secret (spec 009). Any generated parameter makes the
  secret dynamic.
- `GET` resolves per effective user, adds each generated key to `redact_keys`, serves the stored
  provider, and `expires_at` = the earliest generated expiry.
- At a grant's exchange, every exchange generator of a secret the actor may use is minted for the
  user, with a refresh token, as spec 010 did for `token_exchange` secrets.
- `auth.Caller` carries the verified token's claims (read only); under a grant, the user's, taken at the
  grant's exchange.
- **Migration**: `provider: token_exchange` stays an alias: a `mint+exchange://<audience>?scope=<scope>`
  generator on the type's token parameter (`http.bearer_token`, `quack.token`), served with provider
  `token_exchange` as stored. Its audience and scope are its own, never generated. Existing stores and
  tests keep working.

### The client

No change. A descriptor's `provider` is served as is, except a dynamic S3-family secret (`tresor`, for
httpfs's `REFRESH auto`, spec 006); the service's `redact_keys` are honoured. `test/sql/attach/
dynamic_params.test` proves it against the fake: an `http` secret with provider `config` and an `mssql`
secret with provider `access_token`, generated keys redacted (one, `user`, no name-based net covers).

### Not now

- **`tresor_service_login`** (the service's own login type, never served to lookups, consumed only by
  tresor-server) is **not registered in DuckDB now**: later, by need.
- **Per-user logins** (`mint+login://`) are bound by the service, not by grants: `use` stays granted to
  roles and groups only (spec 009).

## Enforcement & security

- A claim generator serves a claim's text, never the bearer token; the claim is the effective user's.
- A generated value is never empty; a refusal names no token and no stored value.
- An exchange for the service's own audience is refused at PUT and at the mint (spec 010's check).
- Every generated key is redacted by the service; tresor also redacts its name-based net.
- A value stored before this spec that begins with `mint+` but is no valid generator is not served
  (`500 service_error`); a value beginning `mint++` is now served with one `+` dropped.

## Testing

- Go (`server/internal/api/generated_test.go`): validation (kinds, query, own audience, no value in a
  refusal, typed values literal), the escape, claim (direct, under a grant = the grant's user's, the
  node's own, missing/object refused, redact_keys, expiry), exchange of any type (direct, under a grant,
  scope, earliest expiry, mint_refused), the alias.
- `test/sql/attach/dynamic_params.test`: the client against the fake (provider served, redaction).
- `test/sql/conformance/generators.test`, gated by `TRESOR_CONFORMANCE_GENERATORS` (set by
  `scripts/ci/test_keycloak.sh` for the reference server): exchange and claim through DuckDB, with
  Keycloak and `test/keycloak/echo.py` (its `/claim` path answers the bearer value), the escape,
  `mint_refused`.

## Alternatives considered

- A normative generator syntax in the protocol: rejected; the client never sees it, and services differ
  (tresor-server interpolates).
- `\` or `mint:` style escapes: rejected for doubling the `+`, the rule tresor-server's `$${` follows.
- Treating an unknown kind as a literal: rejected; a typo would be served as a credential.

## Follow-ups

- `tresor_service_login` in DuckDB, when a consumer needs it.
- Interpolation in the reference server, if a test needs it.
