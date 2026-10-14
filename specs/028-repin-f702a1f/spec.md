# Spec 028: re-pin duckdb to f702a1f - with duckdb-acl

- **Status**: implemented
- **Date**: 2026-10-14
- **Author**: hugr lab
- **Asked by**: the owner: tresor re-pins itself; duckdb-acl re-pins hugr-node and acl-otel (duckdb-acl #227 /
  spec 128) - the distribution build, which compiles the branch head, broke on hugr-node

## Summary

The duckdb submodule moves from bba7360 to f702a1f, the head of `v2.0-cyanoptera` on 2026-10-14 (229 commits).
With it httpfs 23b865d -> abdd053 (duckdb's tree's pin), and `ACL_COMMIT` to duckdb-acl #227. extension-ci-tools
(39ffc46) and duckdb-ext-common (v0.12.0) stay.

## What changed in duckdb that tresor meets

Nothing in tresor's code:
- #27108, a statement that expands into several runs as one query (`StreamsByDefault` takes the result, prepared
  expanding statements defer their metadata): tresor prepares and runs no statements of its own.
- #26914, `ExpressionStatement` moved to the shell: not used.
- The CLI's agent output mode: every script that reads the CLI's output passes `-no-agent` (specs/019).

## Testing

At f702a1f, locally: `test/sql/*`; `test_attach.sh` on both HTTP clients, and with `TRESOR_TEST_HTTPFS=1`
(1046 assertions, `embedded.test` included); `smoke_load.sh`; `test_keycloak.sh` with duckdb-acl #227 (72
assertions); the wasm build.

## Follow-ups

- `ACL_COMMIT` to #227's merged commit.
