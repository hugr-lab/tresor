# Spec 021: re-pin duckdb to 4fbae43 - with duckdb-acl and acl-otel

- **Status**: implemented
- **Date**: 2026-10-07
- **Author**: hugr lab
- **Asked by**: the owner, through duckdb-acl's session: the three extensions move together (acl spec 104,
  hugr-lab/duckdb-acl#184; acl-otel spec 016)

## Summary

The duckdb submodule moves from eb0d9df to 4fbae43, the head of `v2.0-cyanoptera` on 2026-10-07 (364
commits; still no v2.0.0 tag). Nothing else moves:
- httpfs: duckdb's tree still pins 5e34903 (`.github/config/extensions/httpfs.cmake`);
- extension-ci-tools 39ffc46 and duckdb-ext-common v0.10.0: what duckdb-acl #184 pins too;
- `ACL_COMMIT`: duckdb-acl with #184 (spec 104), whose duckdb is 4fbae43 - merged as 7758874.

## What changed in duckdb that tresor meets

- **HTTP logs redacted by default** (#26522, `redact_http_logs`). `HTTPParams` now borrows the opener's
  database to read the setting; without one it redacts. tresor's DuckDB transport (specs/020) gives
  DuckDB's client an opener with no database and no logger, so its requests are neither logged nor, if
  they were, unredacted.
- **An ATTACH path with an explicit `TYPE` is not a remote file** (#26410). tresor's path has no scheme
  and its prefix names the type (`tresor:host`); the test that pins "an `https://` path makes duckdb
  require httpfs and force READ_ONLY" still holds - it gives no `TYPE`.
- **The CLI's agent mode** can be forced with `DUCKDB_AGENT_MODE=1/0` (#26416); tresor's scripts already
  pass `-no-agent` (specs/019).

## Testing

- `test/sql/*`, `test_attach.sh` on the built-in client and on DuckDB's (`TRESOR_HTTP_CLIENT=duckdb`),
  `smoke_load.sh`, and the wasm build (`make wasm_eh`) at 4fbae43.
- `test_keycloak.sh` with real duckdb-acl (#184, c8d1a18): the reference server's tests, sessions run as their
  users and their grants revoked, an administrator through the node, acl's never set, private_key_jwt.
- **A build tree from before** needs `build/release` removed, and vcpkg at the repository's pin (`make
  vcpkg-setup`): the httpfs manifest now asks for curl 8.21.0, which an older vcpkg's version database lacks.

## Follow-ups

- `ACL_COMMIT` to duckdb-acl's merged #184 commit - done: 7758874.
