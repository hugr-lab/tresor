# Spec 036: DuckDB's sandbox stops tresor's own requests - enable_external_access on either client

- **Status**: implemented
- **Date**: 2026-10-17
- **Author**: hugr lab
- **Asked by**: the owner (specs/035): before the first release, `enable_external_access = false` must stop
  tresor's requests too - specs/023's follow-up

## Summary

An administrator who sets `enable_external_access = false` expects DuckDB to reach nothing outside. tresor's
requests - the service's API, the identity provider's discovery, grants and revocation - went out regardless:
- the built-in client (the default) never asked DuckDB;
- DuckDB's client did not either, unlike specs/023 assumed: `HTTPUtil::Request` checks only a request whose
  parameters name a database, and tresor's opener names none (so DuckDB adds nothing of its own to tresor's
  requests).

Now both ask DuckDB's sandbox before every request, as DuckDB asks for its own: `DBConfig::CanAccessFile(url)`,
which honours `enable_external_access` and the URLs `allowed_directories` / `allowed_paths` name.

## Design

- **One check, both clients**: `tresor_http_client = 'builtin'` gets a transport too (`BuiltinTransport`) that
  checks, then hands the request to the OIDC core's built-in client (a transport calling back into the core
  reaches it); the DuckDB transport checks first, for every method - PATCH included, which goes to the built-in
  client natively.
- **At the moment of the request**: the setting is read when a request is made, so `SET enable_external_access =
  false` after an ATTACH stops that catalog's calls from then on (DuckDB cannot turn it back on). What was fetched
  before is served from memory until it expires, as any secret DuckDB holds.
- **Refused as DuckDB refuses**: a transport error in DuckDB's own words ("Cannot access "<url>" - file system
  operations are disabled by configuration"), inside tresor's message for the call (discovery, the secret, a
  login). The URL is an endpoint's: it carries no token or secret.
- **Allowed endpoints**: `allowed_directories = ['https://secrets.corp.example/', 'https://login.corp.example/']`
  set before external access is turned off lets tresor reach those, as it lets DuckDB.
- **Every request is covered**: every call tresor makes runs under an `HttpScope` (the ATTACH, a login and its
  thread, a session's calls and renewals, the actor's exchanges and revocations, `tresor_logoff`'s revocation);
  the OIDC core's own requests inside a grant ride the scope's transport.
- **Not network**: the OS credential store (specs/012) is local and stays usable; a logoff still removes a
  remembered login when its revocation is refused. The files a login reads were already bounded by the sandbox
  (specs/015).
- **duckdb-acl**: it turns the setting off only in its own scratch database, where tresor is not loaded - a node
  is unaffected.

## Testing

- `test/sql/attach/external_access.test` (both clients, through `test_attach.sh`): after `SET
  enable_external_access = false`, a secret not fetched yet is refused, one fetched before is still served, a new
  ATTACH and `tresor_login` are refused. Without the DuckDB transport's check, the refusal does not happen on
  `tresor_http_client = 'duckdb'` (checked).
- `test/sql/attach/external_access_allowed.test`: with the fake service's URL in `allowed_directories`, ATTACH,
  whoami and a secret work with external access off.
- `service_identities.test`'s sandbox case allows the service's URL, so it still proves that a credential file
  outside `allowed_directories` is refused.

## Implementation

- `src/tresor_http.cpp`: `Refusal`, `BuiltinTransport`; `TransportFor` returns it for `builtin`; `Send` (the
  DuckDB transport) checks first.
