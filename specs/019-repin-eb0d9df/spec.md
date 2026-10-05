# Spec 019: re-pin duckdb to eb0d9df - the CLI's agent mode, duckdb-acl's issuers

- **Status**: implemented
- **Date**: 2026-10-05
- **Author**: hugr lab
- **Asked by**: the owner, through duckdb-acl's session: the three extensions stay on one duckdb commit

## Summary

The duckdb submodule moves from a2af0a7 to eb0d9df, the head of `v2.0-cyanoptera` on 2026-10-05 (340
commits). httpfs moves to that tree's pin, 5e34903. duckdb-acl (#179, spec 100) and acl-otel move to
the same commit. tresor's own code needs no change: the parser API that moved (`ParserOptions`,
`Parser::ParseExpressionList`) is not used here.

## What changed for the tests

- **The CLI's agent mode.** duckdb's CLI changes its output format when it runs under an AI agent
  (`CLAUDECODE`, `CODEX_*`, `AI_AGENT` set) and its stdout is not a terminal. Every script that reads the
  CLI's output now passes `-no-agent`: `test_keycloak.sh`, `smoke_load.sh`, `entra_live.sh` and
  `otel_live.sh`.
- **duckdb-acl's issuers (acl spec 095).** `acl_define_issuer(issuer, jwks, audience, alg, role claim,
  claim map)` is gone. `test/acl/actor.sql` now uses `ACL ADMIN CREATE ISSUER '<issuer>' AUDIENCES
  ('acl-node') ROLE CLAIM 'realm_access.roles'`, whose keys come from the issuer's discovery.
  - acl reads keys only from allowed locations (acl spec 071), by default `https://`. The test's Keycloak
    is plain http on loopback, so the test allows `http://127.0.0.1:` (`acl_jwks_locations`).
  - The JWKS that `test_keycloak.sh` passed in is no longer needed.
- **A build tree** that already fetched httpfs at the old pin needs `build/release/_deps/*_extension_fc-*`
  and `build/extension_configuration/_deps` removed before the rebuild.

## Testing

- `test/sql/*`, `test_attach.sh` (the fake), `test_keycloak.sh` (conformance, the reference server's
  tests, private_key_jwt) and `smoke_load.sh` pass at eb0d9df.
- `test_keycloak.sh` with a real duckdb-acl (`ACL_COMMIT` on duckdb-acl #179, duckdb eb0d9df) passes:
  sessions, grants, an administrator through the node, and acl's never set for `act_for_sessions`.

## Follow-ups

- `ACL_COMMIT` moves to #179's commit on duckdb-acl main once it merges.
