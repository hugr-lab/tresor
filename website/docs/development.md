---
sidebar_position: 6
title: Development
---

# Development

## Build and test

```bash
git clone --recurse-submodules https://github.com/hugr-lab/tresor.git
cd tresor
GEN=ninja make                              # duckdb (2.0 line) + tresor
build/release/test/unittest 'test/sql/*'    # sqllogictests
scripts/ci/smoke_load.sh                    # the artifact, used out of tree, loaded by ATTACH alone
```

tresor is built `DONT_LINK`: the test shell does not contain it, so a test can prove that an
`ATTACH 'tresor:…'` loads the installed extension by itself. Tests load it by build path
(`LOAD '__BUILD_DIRECTORY__/extension/tresor/tresor.duckdb_extension'`) or install it from the
build's local repository.

## Pins

tresor rides the **2.0 line** at the same duckdb commit as
[duckdb-acl](https://github.com/hugr-lab/duckdb-acl) and acl-otel: on a server the three load into
one DuckDB, and loadable extensions must match the host's duckdb exactly. Bump the pins together.

## Repository layout

| Path | What |
| --- | --- |
| `src/` | the extension |
| `duckdb-ext-common/` | submodule: shared contracts and hook bases (the audit hook tresor publishes lives there) |
| `server/` | the reference `duckdb-secrets/1` server (for tests and as an example) |
| `website/` | this site; the [protocol](./protocol.md) page is the specification |
| `specs/` | one lightweight spec per feature |

## Docs

```bash
cd website && npm ci && npx docusaurus start
```
