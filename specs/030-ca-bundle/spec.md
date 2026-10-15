# Spec 030: DuckDB's `ca_cert_file` for tresor's built-in client

- **Status**: implemented
- **Date**: 2026-10-15
- **Author**: hugr lab
- **Asked by**: the owner (2026-10-15): a duckdb-acl / hugr-node node could not reach a tresor service or an IdP
  behind a private CA
- **Module side**: duckdb-ext-common specs/016-oidc-ca-bundle (PR #15)

## Summary

tresor's built-in HTTP client - the OIDC core of duckdb-ext-common - verified https against the system's roots
only, so a service or an identity provider whose certificate a private CA issued could not be reached, although
DuckDB's `ca_cert_file` was set. Now every request of the built-in client trusts the certificates in
`ca_cert_file` **beside** the system's roots. `tresor_http_client = 'duckdb'` already honoured the setting
(specs/020); nothing changes there.

## Problem

A node (duckdb-acl, hugr-node) behind a corporate CA sets `ca_cert_file` for httpfs. tresor's default client
ignored it: `ATTACH 'tresor:secrets.corp.internal'` failed with `SSL server verification failed`, and so did a
token renewal, `tresor_login`, the actor's exchanges and `tresor_logoff`'s revocation. Such a node also calls a
public IdP (Entra), so a bundle that replaced the system's roots would not do.

## Design

- **The module** (duckdb-ext-common spec 016): `oidc::CaBundleScope` / `SetDefaultCaBundle`, the bundle a PEM
  file added to each https client's own store with the system's roots kept on. An unreadable bundle, or one
  without a certificate, fails the request; verification is never off.
- **tresor** (`src/tresor_http.*`):
  - `CaBundleFor(context)`: `ca_cert_file` as the context sees it (a `SET` or a `SET GLOBAL`). It is httpfs's
    setting: without httpfs loaded there is none, and the system's roots alone count. (DuckDB's client, below,
    reads only the global value.)
  - `HttpClient {transport, ca_bundle}` (`HttpClientFor(context)`), and `HttpScope`, which puts both of the
    OIDC core's thread scopes in force: the transport `tresor_http_client` names (specs/020) and the bundle.
  - Installed wherever a `TransportScope` was: `Login` (the ATTACH: discovery, the IdP's flows, the first
    whoami), `StartPersonLogin` and its background thread (`tresor_login`; the thread gets the client by value),
    `HandOverLogin` (`tresor_web_login`'s discovery), `tresor_logoff` (discovery and revocation), and the
    session's `Call`, `ExchangeForService` and `OwnAudiences` - every call, renewal and actor exchange.
  - **A session keeps the bundle of its ATTACH**, as it keeps the transport (`SetHttpClient`): a long-lived
    catalog does not change its trust when the setting changes later; a new ATTACH reads the setting again.
- **With `tresor_http_client = 'duckdb'`** DuckDB's client reads `ca_cert_file` itself, per request
  (`TresorHttpOpener`), and httpfs uses it **instead of** the system's roots (httplib's and curl's behaviour
  with a CA file). The scope is installed there too, and matters only for the request DuckDB's client cannot
  make, `PATCH`, which falls back to the built-in client.
- No protocol change, no contract change.

## Enforcement & security

- Verification is always on, for the chain and the host name; a bundle only adds trust anchors.
- No fallback: a bundle named but unusable fails the request (the error names the file, never its content).
- The bundle is read on each request, so a rotated file counts at once for a new connection.

## Testing

`test/sql/attach/ca_bundle.test`, run by `scripts/ci/test_attach.sh` on both clients (`TRESOR_HTTP_CLIENT`):
the script makes a private CA and a certificate from it for 127.0.0.1, and the fake service
(`test/fake/fake_service.py --tls-port-file/--tls-cert/--tls-key`) also answers https on a second port. No
`INSECURE_HTTP` anywhere in the test.
- on the run's client: an ATTACH without `ca_cert_file` fails verification; with `SET GLOBAL ca_cert_file` it
  attaches (discovery, client credentials at the IdP, whoami over https); another certificate as the file fails;
- on the built-in client: the module's own error; a missing file and a file without a certificate fail the
  ATTACH; a session attached with the file goes on after `RESET`, while a new ATTACH does not;
- `tresor_login` with the device flow over https (its background thread polls with the bundle), the ATTACH that
  takes it up, and `tresor_logoff`'s revocation over https.

The module's own test proves the bundle sits beside the system's roots (spec 016).

## Alternatives considered

- Reading `ca_cert_file` per request from the instance in the session (as DuckDB's client does): a session
  outlives the context it was attached in, and the built-in client's transport is taken at ATTACH already; the
  bundle follows it.
- A tresor setting of its own: one setting for DuckDB's whole trust is simpler to run.

## Follow-ups

- The duckdb-ext-common tag after its PR #15 merges; then the submodule moves from the PR's commit to the tag,
  and `CLAUDE.md`'s pin row names it (not done here: the tag does not exist yet).
