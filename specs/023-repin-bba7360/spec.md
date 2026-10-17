# Spec 023: re-pin duckdb to bba7360 - with duckdb-acl and acl-otel

- **Status**: implemented
- **Date**: 2026-10-12
- **Author**: hugr lab
- **Asked by**: the owner: the three extensions move together (duckdb-acl #217 / spec 123; acl-otel after it)

## Summary

The duckdb submodule moves from 4fbae43 to bba7360, the head of `v2.0-cyanoptera` on 2026-10-12 (841
commits; duckdb-acl first took 664aafa that morning, then the head moved 63 more). With it:
- httpfs 5e34903 → 23b865d, the commit duckdb's tree now pins (`.github/config/extensions/httpfs.cmake`);
- duckdb-ext-common v0.11.0 → v0.12.0, as duckdb-acl: it adds a contract (`acl_lineage_sources.hpp`) tresor
  does not use; ACLC stays 2, ACLA 3;
- `ACL_COMMIT`: duckdb-acl #217 (spec 123), whose duckdb is bba7360 - merged as 05dd910;
- extension-ci-tools unchanged (39ffc46).

## What changed in duckdb that tresor meets

Nothing in tresor's code. Checked against what other re-pins met:
- `TableFunction::get_bind_info` became `get_table_entry` (cb8eeaef): tresor's table functions use neither.
- Scalar arguments are cast before the bind callback (fd4f336): tresor's scalars (`variable`,
  `tresor_secret_param`, `tresor_version`) have no bind callback and take VARCHARs.
- A result closed before its query finished now aborts it; a new query on a connection with an open result
  fails (ef5b57f, 3f22451, 3a36a88); planner eagerness is gone (#26880: `ResultEagerness` removed, a submitted
  result left to its consumer): tresor runs no queries of its own on DuckDB connections, and uses neither.
- `enable_external_access` is now checked centrally in `HTTPUtil::Request`: tresor's DuckDB transport
  (specs/020) goes through it; its built-in client does not - a follow-up below.

## Testing

At bba7360, locally: `test/sql/*`, `test_attach.sh` on both HTTP clients (918 + 918), `smoke_load.sh`,
`test_keycloak.sh` with duckdb-acl #217 (72 assertions: sessions, grants revoked, an administrator through the
node, acl's never set, private_key_jwt), and the wasm build.

## Follow-ups

- tresor's built-in HTTP client and `enable_external_access` (whether a disabled setting stops tresor's own
  requests to the IdP and the service): its own spec. Done: specs/036 - which found the DuckDB transport not
  checked either (its opener names no database, so `HTTPUtil::Request` skips the check); both are now.
