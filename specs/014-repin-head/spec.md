# Spec 014: re-pin duckdb to the head of v2.0-cyanoptera (no more DONT_LINK)

- **Status**: implemented
- **Date**: 2026-09-30
- **Author**: hugr lab
- **Found by**: the distribution build, which compiles the head of `v2.0-cyanoptera`, failed on every
  main push since d412b6f:
  `'class duckdb::TableFunction' has no member named 'named_parameters'`.

## Summary

The duckdb submodule moves from d4e7256 (2026-09-22) to a2af0a7, the head of `v2.0-cyanoptera` on
2026-09-30, on the owner's decision to take the current head. httpfs moves with it to 3f81d97.
duckdb-acl and acl-otel re-pin to the same commit; `ACL_COMMIT` follows once duckdb-acl has.

## Problem

Upstream changed two things tresor relies on:

- **Function signatures**: a table function's parameters are a `FunctionSignature`, no longer
  `named_parameters`. `tresor_logoff`'s `issuer`, `client_id` and `service` were named parameters.
  A secret function (`CreateSecretFunction`) keeps its `named_parameters`.
- **`DONT_LINK` is gone** (duckdb #26189). An extension is linked statically only when an extension config
  names it with `duckdb_extension_statically_link()`, or `STATICALLY_LINK_EXTENSIONS` does. The default set
  is `core_functions;parquet;json;icu`.

## Design

- **`tresor_logoff`**: its options are typed kwargs (`WithTypedKwargs("options", …)`). An option the call
  leaves out is not passed at all, so the bind's checks are unchanged: a NULL value is still refused.
- **`extension_config.cmake`**:
  - tresor and acl lose `DONT_LINK`. Not being linked is now the default, which is what both need: tresor
    must be loaded by ATTACH, and acl must not rewrite every other test.
  - httpfs and acl_stub, which the test build links, are named with `duckdb_extension_statically_link()`.
- The prose that said `DONT_LINK` (CLAUDE.md, the development page, a test's comment) says "never
  statically linked".

## Enforcement & security

No behaviour changes: the same function, with the same options and the same refusals.

## Testing

Against the new pin:

- `test/sql/*` passes;
- `test_attach.sh` passes (the fake service, no skips);
- `test_keycloak.sh` passes: conformance, the reference server's tests and private_key_jwt. In CI its
  duckdb-acl part runs against duckdb-acl a5a6e14 (#169, spec 091, duckdb a2af0a7).
- `test/sql/logoff_options.test` (new) pins what the typed kwargs keep:
  - NULL is refused;
  - names match in any case;
  - an unknown name is refused.
- The distribution build is run on the branch, at the head.

## Follow-ups

- `ACL_COMMIT` is a5a6e14, duckdb-acl main with #169 (spec 091).
