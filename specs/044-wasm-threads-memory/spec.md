# Spec 044: wasm_threads that a threads DuckDB-wasm can load - shared memory

- **Status**: implemented
- **Date**: 2026-10-22
- **Author**: hugr lab (found running tresor in hugr-platform's DuckDB-wasm build, at the duckdb-acl session's request)

## Summary

tresor's `wasm_threads` build (and every `wasm_threads` extension DuckDB's pipeline builds, `icu` included) imports a
**plain** memory, while a threads build of DuckDB-wasm has a **shared** one: the browser cannot link them, and `LOAD`
fails with an empty "could not be loaded". DuckDB adds `-pthread -sSHARED_MEMORY=1` to a loadable extension's link
only when the CMake option `USE_WASM_THREADS` is on, and extension-ci-tools' `wasm_threads` goal does not turn it on.
tresor's Makefile does, for `make wasm_threads`; its threads build then loads and runs in a threads DuckDB-wasm.

## Problem

- `duckdb/CMakeLists.txt`: `if(USE_WASM_THREADS) set(WASM_THREAD_FLAGS -pthread -sSHARED_MEMORY=1)`;
  `extension/extension_build_tools.cmake` links a wasm loadable extension with `${WASM_THREAD_FLAGS}`.
- `extension-ci-tools/makefiles/duckdb_extension.Makefile`: `wasm_threads` passes `-pthread` and
  `-DWITH_WASM_THREADS=1` in `CMAKE_CXX_FLAGS`, never `-DUSE_WASM_THREADS=1`.
- So the side module's memory import has no shared flag: seen in tresor's distribution artifact and in
  `extensions.duckdb.org/v2.0.0/wasm_threads/icu.duckdb_extension.wasm` alike. hugr-platform's threads build of
  DuckDB-wasm (51ee2cc, emscripten 6.0.9) loads none of them.

## Design

- `Makefile`: `EXT_FLAGS += -DUSE_WASM_THREADS=1` when the goal is `wasm_threads` - the distribution workflow and
  community-extensions' build both run `make wasm_threads` in this repository, so both take it. Other goals are
  unchanged.
- `scripts/ci/wasm_imports.py --memory shared|plain <extension>`: the memory the extension imports.
- `distribution.yml`: a `wasm memory` job after the build - `wasm_threads` shared, `wasm_eh` and `wasm_mvp` plain.
  `test_wasm.sh` checks `wasm_eh` plain too.

## Testing

- Locally: `OVERRIDE_GIT_DESCRIBE=v2.0.0 make wasm_threads` (emsdk 6.0.9) - the memory import shared, every import
  resolved against hugr-platform's `duckdb-threads.wasm`; then in Chromium with cross-origin isolation, through the
  helper `attachTresor` and that build's `AsyncDuckDB` (threads bindings): the signed extension verified and loaded,
  the page's token handed over, ATTACH, whoami (`page`, alice), the secrets, a variable, a renewed token, another
  user's token (whoami: Bob). The distribution artifact without the flag fails the same run at LOAD.
- The same run on that build's `wasm_eh` bindings with the distribution artifact (f4ea5fb): all passed.
- CI: `distribution.yml`'s `wasm memory` job (main and tags).

## Follow-ups

- Upstream: extension-ci-tools' `wasm_threads` goal should pass `-DUSE_WASM_THREADS=1` (or DuckDB tie the link flags
  to `WITH_WASM_THREADS`); then this Makefile line goes.
- A browser run of `wasm_threads` in CI needs a threads DuckDB-wasm build to pin (hugr-platform's release, or
  DuckDB-wasm's own once published on 2.0).
