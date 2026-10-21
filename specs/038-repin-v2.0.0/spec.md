# Spec 038: re-pin to DuckDB v2.0.0 - the release tag, with duckdb-acl

- **Status**: accepted (local gate green; with duckdb-acl's spec 141: CI)
- **Date**: 2026-10-21
- **Author**: hugr lab
- **Asked by**: the owner (relayed by duckdb-acl, 2026-10-21): the family moves onto DuckDB v2.0.0, released that day;
  duckdb-acl leads (its spec 141)

## Summary

DuckDB v2.0.0 is out: the tag `v2.0.0` is d54cbbe (77 commits after our f8f3f4d; the `v2.0-cyanoptera` branch
has moved past it). The pins follow, as specs/017's checklist says, and as duckdb-acl's spec 141 chose:

- **duckdb** -> d54cbbe, the tag's commit (not the branch head).
- **The test-only extensions**, as duckdb's tree pins them at the tag (`check_extension_pins.sh`): httpfs
  2174b46 -> 77392a7 and iceberg 10eafd0 -> 4c0c087, both now without patches (duckdb dropped them);
  postgres_scanner c0f5a3c and avro 758fb60 stay.
- **extension-ci-tools** 39ffc46 -> fe955ed, main's head - not its `v2.0-cyanoptera` branch, which lacks #432
  (clang-cl opt-in on Windows) and #434; no `v2.0.0` branch exists. Main also turns osx_amd64 off unless
  opted in (not our platform) and can hand over a prebuilt duckdb - the Makefile's override stays (#59).
- **distribution.yml**: `duckdb_version: v2.0.0` (was the branch), `uses: …@main`, `ci_tools_version: main`.
  The distribution stamps the extension for `v2.0.0`, which the released DuckDB loads; a local build reports
  `v2.0.0-devN` (DuckDB 2.0 derives a source build's version from its release file, not `git describe`).
- **duckdb-ext-common** v0.13.0 stays; `ACL_COMMIT` moves to duckdb-acl's spec 141 merged commit.

## What changed in duckdb that tresor meets

- `HTTPParams::access_path`: the sandbox check of `HTTPUtil::Request` may name a file system's path instead of
  the URL. tresor checks its own requests (specs/036) and sets no database on its params - unchanged.
- No change to the secret manager, the storage or catalog interfaces tresor implements.

## Testing

At d54cbbe, locally (macOS, `GEN=ninja`, `TRESOR_TEST_HTTPFS=1 TRESOR_TEST_CONSUMERS=1`): `test/sql/*`;
`test_attach.sh` on both HTTP clients (1185 assertions each); the consumers with a Postgres in docker (58);
`smoke_load.sh`; the wasm build. With duckdb-acl's spec 141: `test_keycloak.sh` (the actor against real
duckdb-acl), CI, and the Distribution build dispatched on the branch before the merge.

## Follow-ups

- `ACL_COMMIT` to spec 141's merged commit.
- The first release (0.1.0): specs/017's checklist, the owner's go.
