# Spec 031: re-pin duckdb to 7304f7b - with duckdb-acl

- **Status**: implemented
- **Date**: 2026-10-15
- **Author**: hugr lab
- **Asked by**: the owner: the family moves together (duckdb-acl spec 131); tresor re-pins itself the same day

## Summary

The duckdb submodule moves from f702a1f to 7304f7b, the head of `v2.0-cyanoptera` on 2026-10-15 (554 commits).
httpfs stays abdd053 (duckdb's tree pins the same), extension-ci-tools 39ffc46 and duckdb-ext-common v0.13.0
stay; `ACL_COMMIT` moves to duckdb-acl's spec 131.

## What changed in duckdb that tresor meets

- **An http secret's extra headers are redacted** (#27257, "redact HTTP headers in secrets"): DuckDB now hides
  `extra_http_headers` as it hides `bearer_token`. tresor builds its secrets through DuckDB's own types, so a
  service's http secret is redacted the same way: `tresor_secret_param(name, 'extra_http_headers')` answers
  `MAP(VARCHAR, VARCHAR) <redacted>`. Two tests that read the value back now assert the typed, redacted form
  (`attach/writes.test`, `reference_server/actor.test`); what they prove - the secret written and found, the
  node's secret served under the grant - is proven by the lines beside them.
- HTTP retries reworked (the operation loop owns the outcome): tresor's DuckDB transport asks for no retry
  (`retries = 0`, `try_request`) - unchanged, the suites pass on both clients.
- The secret manager snapshots its storages under its lock for `AllSecrets`: tresor's storage is unchanged.

## Testing

At 7304f7b, locally: `test/sql/*`; `test_attach.sh` with `TRESOR_TEST_HTTPFS=1` on both HTTP clients (1110
assertions); `smoke_load.sh`; `test_keycloak.sh` (the reference server's tests, conformance); the wasm build.
With duckdb-acl's spec 131: CI.

## Follow-ups

- `ACL_COMMIT` to spec 131's merged commit. Done: ce1d417 (#53).
