# Spec 034: re-pin duckdb to f8f3f4d - with duckdb-acl

- **Status**: implemented
- **Date**: 2026-10-17
- **Author**: hugr lab
- **Asked by**: the owner (relayed by tresor-server): the latest DuckDB 2.0 - no 2.0 release yet, so the head of
  `v2.0-cyanoptera`; the family moves together (duckdb-acl leads)

## Summary

The duckdb submodule moves from 7304f7b to f8f3f4d, the head of `v2.0-cyanoptera` on 2026-10-16 (69 commits).
The test-only extensions move with duckdb's tree (`check_extension_pins.sh`): httpfs abdd053 -> 2174b46, iceberg
5b9ff89 -> 10eafd0, postgres_scanner 9671d2c -> c0f5a3c; avro stays 758fb60. extension-ci-tools 39ffc46 and
duckdb-ext-common v0.13.0 stay; `ACL_COMMIT` moves to duckdb-acl's spec 133 (#233, 00375b8: duckdb f8f3f4d,
quack e7a9be3, postgres c0f5a3c).

## What changed that tresor meets

- **httpfs 2174b46** carries what duckdb patched before (its 0004 and 0005 patches are gone from duckdb's tree;
  0006, S3's RequestTimeout as a retry, stays) and reads CA bundles through DuckDB's file system: tresor's DuckDB
  transport passes `ca_cert_file` as before (specs/030) - `attach/ca_bundle.test` passes on both clients.
- **iceberg 10eafd0** needs parquet at load (linked in every build).
- No change to tresor's sources: nothing in the 69 commits touches the secret manager, the storage or the
  catalog interfaces tresor implements.

## Testing

At f8f3f4d, locally (macOS, `GEN=ninja`, `TRESOR_TEST_HTTPFS=1 TRESOR_TEST_CONSUMERS=1`):
- `test/sql/*`;
- `test_attach.sh` on both HTTP clients: 1130 assertions each - specs/032's typed secrets and specs/030's CA
  bundle among them;
- the consumers (specs/033) with a Postgres in docker: 58 assertions;
- `smoke_load.sh`;
- the wasm build (`make wasm_eh`).

- `test_keycloak.sh` with duckdb-acl #233 (the reference server, conformance, the actor against real duckdb-acl):
  111 assertions.

With duckdb-acl's spec 133: CI.

## Follow-ups

- `ACL_COMMIT` to spec 133's merged commit.
