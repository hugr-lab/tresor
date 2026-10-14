# Spec 024: tresor built into another extension - `tresor_sources.cmake`, `LoadTresorCore`

- **Status**: implemented
- **Date**: 2026-10-14
- **Author**: hugr lab
- **Asked by**: the owner (relayed by duckdb-acl's session): hugr-node's `hugr_node` always builds tresor in, as it
  builds duckdb-acl in (duckdb-acl spec 127, PR A #222)

## Summary

The platform node's extension `hugr_node` (hugr-lab/hugr-node, BUSL, Linux amd64/arm64) is one extension built from
duckdb-acl's sources, tresor's and its own. tresor gets the same two embedding hooks duckdb-acl has: a CMake file
that says what tresor compiles and links, and a load function the embedder's entry point calls. tresor's own build
uses both and is unchanged.

## Design

- **`tresor_sources.cmake`** (repository root) - everything `CMakeLists.txt` set inline:
  - `TRESOR_ROOT` (this repository) and `TRESOR_SOURCES` - tresor's sources by `${TRESOR_ROOT}/...` path, the
    duckdb-ext-common `oidc/` and `keychain/` modules' sources with them. A list of its own name, not
    `EXTENSION_SOURCES`: duckdb-acl's `acl_sources.cmake` sets that one, and an embedder includes both.
  - the include directories: `src/include`, duckdb-ext-common `hooks/` and `contracts/`, the modules' `include/`,
    and duckdb's bundled httplib and yyjson from `${CMAKE_SOURCE_DIR}/third_party/...` - the duckdb the build runs
    from (in tresor's own build that is the `duckdb/` submodule, so the same paths), never tresor's submodule by
    path.
  - OpenSSL from vcpkg, static, the machine's prefixes ignored (as before).
  - the modules' compile definitions - `DUCKDB_EXT_COMMON_OIDC_NAMESPACE=tresor`, `DUCKDB_EXT_COMMON_OIDC_TLS=1`,
    `DUCKDB_EXT_COMMON_KEYCHAIN_NAMESPACE=tresor` - as **properties of tresor's sources**, not of a target.
    duckdb-acl's `acl_configure_targets` defines `DUCKDB_EXT_COMMON_OIDC_NAMESPACE=acl` on the whole target; in
    `hugr_node` that target is also tresor's, and a target-wide `=tresor` beside it would hand one of the two
    copies of the OIDC core the other's names. A source's definitions follow its target's on the compile line, so
    tresor's sources are `tresor` whatever the target says (the embedding test proves it with a conflicting
    target-wide definition). duckdb's own `set_extension_version_sources` uses the same mechanism.
  - `tresor_configure_targets(<targets...>)`: OpenSSL, the keychain module's libraries, the Security framework
    (macOS), winsock/crypt32/shell32 (Windows) on the targets; with `TRESOR_EMBEDDED` also that definition on
    them, so the embedder's own sources read `tresor_extension.hpp` as tresor's do.
  - Source properties are directory-scoped in CMake: an embedder includes the file from the directory that creates
    its targets (duckdb's `build_*_extension` do; so does the oidc module's own visibility property).
- **`CMakeLists.txt`**: the header, `include(tresor_sources.cmake)`, the two targets from `TRESOR_SOURCES`,
  `tresor_configure_targets`, the install. The same sources, flags and libraries as before - compared on the
  generated compile commands and link lines of a release build (below).
- **`LoadTresorCore(ExtensionLoader &)`** (`src/include/tresor_extension.hpp`): tresor's whole load (the former
  `LoadInternal`: the ATTACH type, the secret type, the audit, the keychain, the HTTP client setting, every
  `tresor_*` function). Returns nothing - unlike `LoadAclCore` there is no store an embedder registers against.
- **`TRESOR_EMBEDDED`**: an embedder sets the CMake variable before the include; `tresor_sources.cmake` defines the
  macro on tresor's sources (and `tresor_configure_targets` on the targets). Under it tresor's
  `DUCKDB_CPP_EXTENSION_ENTRY(tresor, ...)`, `TresorExtension` (declaration and members) and
  `#define DUCKDB_EXTENSION_MAIN` are not compiled - the embedder's entry is the one main.
- **The version**: `TresorExtension().Version()` had two callers, `tresor_version()` and the User-Agent of tresor's
  requests. Both call the free function `TresorVersion()` now: `EXT_VERSION_TRESOR` in tresor's own build (duckdb
  defines it for the extension it builds), else `TRESOR_VERSION`, which `tresor_sources.cmake` defines under
  `TRESOR_EMBEDDED` on `tresor_extension.cpp` from tresor's own git (`duckdb_extension_generate_version` of
  `TRESOR_ROOT`, as duckdb computes an extension's) - so `hugr_node` says tresor's version, not its own.
- No forward declarations were needed (`ExtensionLoader` comes with `duckdb.hpp`); a future one is a `struct` where
  the type is one (MSVC mangles the kind).
- Unchanged: tresor is never statically linked into duckdb's test shell; the distribution build; the protocol.

## Enforcement & security

Nothing changes at run time in tresor's own artifact. An embedded tresor is the same code under the embedder's
entry: the same rules on tokens, the keychain and material (CLAUDE.md "Key rules"). One image then carries one copy
of the duckdb-ext-common contract headers per include order (the embedder's directory sees `include_directories` of
both acl and tresor; whichever duckdb-ext-common comes first answers `acl_connection.hpp` / `tresor_audit.hpp` for
both) - the embedder pins duckdb-acl and tresor at duckdb-ext-common tags with the same contract stamps, as the pin
table already requires when they load into one DuckDB as separate extensions.

## Testing

- **The embedder** (`test/extension/tresor_embedder/`): an extension built the way `hugr_node` is - `set(TRESOR_EMBEDDED
  ON)`, `include(tresor_sources.cmake)`, its own entry calling `LoadTresorCore` and then registering its own
  `tresor_embedder_probe()`. Built in the test build beside acl_stub (`TRESOR_TEST_HTTPFS=1`), loadable only.
  - its target defines `DUCKDB_EXT_COMMON_OIDC_NAMESPACE=embedder` target-wide, as duckdb-acl's configure does on
    `hugr_node`'s target: tresor compiles only if its source-level `tresor` wins;
  - it defines `tresor_duckdb_cpp_init` and `duckdb::TresorExtension::Name()` itself: were `TRESOR_EMBEDDED` to leave
    tresor's entry or `TresorExtension` compiled, the loadable would not link (duplicate symbols) - on GNU ld, the
    Linux CI job's linker (checked: `multiple definition of 'tresor_duckdb_cpp_init'`); Apple's ld (ld-1167)
    lets the duplicate pass under `-dead_strip`, so on macOS the trap is silent;
  - it `#error`s without `TRESOR_EMBEDDED` on its own TU (`tresor_configure_targets`).
- `test/sql/embedded.test`: with autoloading off, the embedder loaded alone - its probe, `tresor_version()` non-empty,
  tresor itself not loaded, both ATTACH spellings reaching tresor's discovery, the `tresor` secret type, a tresor
  setting.
- `test/sql/attach/embedded.test` (`scripts/ci/test_attach.sh`, on both HTTP clients): through the embedder, a
  client-credentials login against the fake service and IdP, `corp.whoami()`, a secret of the service in DuckDB's
  lookup.
- Both `require-env TRESOR_TEST_HTTPFS`; CI's build jobs set it, and the suites' floors forbid that skip.
- Standalone equivalence: the release build's compile commands for tresor's 42 compilations (21 sources, two
  targets) and the tresor targets' link lines, before and after, compared with flags sorted - identical.
- The gate: the release build, `test/sql/*`, `test_attach.sh` on both clients, `smoke_load.sh`, `make wasm_eh`.

## Alternatives considered

- **Target-wide definitions in `tresor_configure_targets`** (duckdb-acl's way): breaks the one target that carries
  both acl and tresor (above).
- **Appending to `EXTENSION_SOURCES`**: an implicit coupling with whatever the embedder or acl's file set it to.
- **A CMake test project outside the duckdb build** (`scripts/ci/test_embed.sh`): a second duckdb configure and
  build for one check; the embedder inside the test build costs only its own compilations and runs in the
  existing suites on every CI platform that builds with `TRESOR_TEST_HTTPFS`.

## Follow-ups

- duckdb-acl: its `acl_configure_targets` could put `DUCKDB_EXT_COMMON_OIDC_NAMESPACE=acl` on acl's sources rather
  than the target, so `hugr_node`'s tresor TUs see one definition instead of a redefinition warning.
- hugr-node: `set(TRESOR_EMBEDDED ON)`, `include(<tresor>/tresor_sources.cmake)`, `${TRESOR_SOURCES}` in its
  sources, `tresor_configure_targets(...)`, `LoadTresorCore(loader)` in its entry; tresor's `vcpkg.json` (openssl)
  in its manifest.
