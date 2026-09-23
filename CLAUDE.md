# tresor — Development Guidelines

tresor is the DuckDB client of an **external secrets service**: `ATTACH 'tresor:<host>' AS corp`
logs in once through any OIDC provider and makes the secrets the caller's role may use part of
DuckDB's own secret lookup; the attached catalog is also the storage for `CREATE PERSISTENT SECRET …
IN corp` and the SQL surface for grants and delegation. The service is anything implementing the
open protocol `duckdb-secrets/1` — its normative text is **`website/docs/protocol.md`**.

Read **[specs/001-architecture/spec.md](specs/001-architecture/spec.md)** first. Deeper research lives
in the local, gitignored `design/001-secrets-service/` (`RESEARCH.md` = the full design history,
revisions 1–10, with every verified duckdb seam; `extension-startup-autoload.md` = how loading by
ATTACH prefix works).

## Technology

- **Language**: C++17 (DuckDB extension standard).
- **Pins — the 2.0 line at duckdb-acl's commit, bumped together with duckdb-acl and acl-otel.** On a
  server the three load into one DuckDB, and loadable extensions must match the host's duckdb
  exactly:

  | Piece | Where | Pin |
  | --- | --- | --- |
  | duckdb | submodule `duckdb/` | branch `v2.0-cyanoptera`, commit = duckdb-acl's |
  | extension-ci-tools | submodule `extension-ci-tools/` | `main`, commit = duckdb-acl's |
  | duckdb-ext-common | submodule `duckdb-ext-common/` | tag `v0.2.0` (the OIDC browser flow + TLS fix; duckdb-acl to follow) |
  | distribution | `.github/workflows/distribution.yml` | `@main`, `duckdb_version: v2.0-cyanoptera` |

- **Dependencies**: OpenSSL from vcpkg (`vcpkg.json`, static, as in duckdb-acl), for the OIDC core
  (duckdb-ext-common `oidc/`, compiled in as `duckdb::tresor::oidc` with `DUCKDB_EXT_COMMON_OIDC_TLS=1`),
  which is tresor's whole HTTP transport: the IdP's flows and the service's API (specs/002).
- **Platforms**: Linux, macOS, Windows; **no wasm** (loopback login, device polling, HTTPS client).

## Project structure

```text
src/                        # the extension: the tresor ATTACH type, tresor_version()
duckdb-ext-common/          # submodule: shared contracts + hook bases; tresor OWNS hooks/ (it is the
                            #   first consumer) and contracts/tresor_*.hpp there (charter R6)
server/                     # the reference duckdb-secrets/1 server (Go) — for tests and as an example
website/                    # docs (docusaurus); docs/protocol.md is the specification
test/sql/                   # sqllogictests; attach/ needs the fake service
test/fake/                  # fake duckdb-secrets service + IdP (Python stdlib) and the fake browser
scripts/ci/                 # smoke_load.sh, test_attach.sh, assert_ran.sh, check_docs_links.py
specs/                      # one lightweight spec per feature (see specs/README.md)
design/                     # LOCAL, gitignored research
```

## Commands

```sh
git submodule update --init --recursive
make vcpkg-setup                            # once (or VCPKG_TOOLCHAIN_PATH=<an existing vcpkg>/scripts/buildsystems/vcpkg.cmake)
GEN=ninja make                              # release: duckdb (2.0) + tresor
build/release/test/unittest 'test/sql/*'    # sqllogictests (test/sql/attach/* skip without TRESOR_TEST_PORT)
scripts/ci/test_attach.sh                   # attach/login tests against test/fake/fake_service.py
scripts/ci/smoke_load.sh                    # out of tree: explicit LOAD, and ATTACH 'tresor:...' loading it alone
find src \( -name '*.cpp' -o -name '*.hpp' \) | xargs clang-format -i      # pin: clang_format==11.0.1
cd website && npm ci && npx docusaurus build                               # docs (onBrokenLinks: throw)
```

**Test-runner rules.** tresor is `DONT_LINK`, on purpose: the test shell must not contain it, or no
test could prove that `ATTACH 'tresor:…'` loads the installed extension. So `require tresor` does not
work — load by build path (`LOAD '__BUILD_DIRECTORY__/extension/tresor/tresor.duckdb_extension'`), or
`INSTALL tresor FROM '__BUILD_DIRECTORY__/repository'` into `SET extension_directories = [...]`
(`extension_directory` is deprecated on 2.0). In gate tests set `autoload_known_extensions = false`. Tests that need a service
`require-env TRESOR_TEST_PORT` and run through `scripts/ci/test_attach.sh` (the fake speaks http on
loopback, so they ATTACH with `INSECURE_HTTP true`; `BROWSER` is the fake browser).

## Code style

DuckDB's conventions: tabs, ≤120 columns, `idx_t`, `unique_ptr`/`optional_ptr`/`reference`, no raw
pointers, braces always, short comments. 2.0 API drift to expect: `ScalarFunction(Identifier(name), …)`,
`Vector::Reference(value, count_t(n))`. Prefer sqllogictest; every feature lands with tests.

## Key rules

- **The ATTACH path has no scheme** (`tresor:host[:port][/base]`, https implied): an `https://` path
  makes duckdb require httpfs and force READ_ONLY before it looks at the type. A test pins this.
- **Never** write secret material to disk, log or emit material / tokens / session handles /
  delegation grant ids, or send an IdP token to anyone but its audience.
- **Login directly with the IdP**, never through the secrets service.
- **A server never adds its own authority** to a user's request (delegation: user's rights ∧ rule ∧
  actor allowed).
- **The protocol page is normative**: a change to requests/responses is a change to
  `website/docs/protocol.md`, in the same PR.
- **Audit**: tresor's own hook (`duckdb-ext-common/contracts/tresor_audit.hpp` on `hooks/`),
  independent of acl; stamped contract, bump on any layout change.

## Working process — per-feature specs

One lightweight spec per feature under `specs/` (see [specs/README.md](specs/README.md)): write it
from `specs/TEMPLATE.md` before or alongside the work, keep it current, supersede instead of
rewriting. Changes spanning duckdb-ext-common / duckdb-acl / acl-otel are specced in each repository.
Do not commit `design/`; do not push without being asked.

## Reference repos (local)

- `~/projects/hugr-lab/duckdb-ext-common` — the charter (specs/001) for contracts and hooks.
- `~/projects/hugr-lab/duckdb-acl` — the OIDC core (spec 060), JWT verification (007/023), the audit
  contract (069), sessions/doors — the server side tresor delegates through.
- `~/projects/hugr-lab/acl-otel` — the audit consumer tresor's hook feeds.
- `~/projects/hugr-lab/mssql-extension` — Azure credential sources (`src/azure/`).
- `~/projects/hugr-lab/mssql-ducklake` — build/CI/docs conventions this repo follows.
