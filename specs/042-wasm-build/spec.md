# Spec 042: the wasm build that loads - no OpenSSL, no sockets; proven in DuckDB-wasm's shell

- **Status**: implemented
- **Date**: 2026-10-22
- **Author**: hugr lab (the owner's request through the duckdb-acl session: tresor in a DuckDB-wasm that another web
  application embeds)

## Summary

tresor's wasm build compiled (specs/020) but could not load: it imported OpenSSL, sockets (`socket`, `connect`,
`getaddrinfo`) and the like, which DuckDB-wasm does not have. A wasm build now has **no built-in HTTP client**: no
OpenSSL, no sockets, no thread of its own (duckdb-ext-common spec 018); every request already went through DuckDB's
client, the browser's, in wasm (specs/020). The build `LOAD`s in DuckDB-wasm on DuckDB v2.0, which CI proves in a
browser: DuckDB-wasm's own shell, the page's login handed over, `ATTACH`, `whoami`, the secrets, a variable. wasm
returns to the distribution build (spec 035 had left it out).

## Problem

- `tresor_sources.cmake` defined `DUCKDB_EXT_COMMON_OIDC_TLS` and linked OpenSSL for every platform. In a wasm side
  module OpenSSL's symbols stay unresolved imports (`SSL_*`, `EVP_*`, `X509_*`, ...).
- The OIDC core compiled duckdb's bundled httplib even without TLS: sockets and name resolution (`getaddrinfo`,
  `getnameinfo`), which DuckDB-wasm's engine does not export.
- Nothing checked it: wasm was compiled by hand and never loaded (DuckDB-wasm was on 1.x until 2026-10-21).

## Design

- **duckdb-ext-common spec 018** (tag v0.15.0): under `__EMSCRIPTEN__` the OIDC core compiles no httplib and starts
  no thread; a request without a transport is refused, the loopback receiver does not start. No header changes.
- **tresor_sources.cmake**: `EMSCRIPTEN` builds define no `DUCKDB_EXT_COMMON_OIDC_TLS`, find and link no OpenSSL.
  `vcpkg.json`: `openssl` with `"platform": "!emscripten"`, so vcpkg builds nothing for wasm.
- **Nothing else changes in wasm**: `tresor_http_client` is `duckdb` (the only one), `tresor_keychain` `memory`, a
  person's login of tresor's own is refused (the page logs in, `tresor_web_login`), the acl actor is refused
  (specs/020). tresor's other `std::thread`s resolve against the engine (its `pthread_create`) and are never
  started in a page.
- **Distribution**: `distribution.yml` builds every platform, wasm included (`wasm_mvp`, `wasm_eh`, `wasm_threads`).
  `description.yml` keeps `excluded_platforms` while `repo.ref` is `v0.1.0`, whose wasm build cannot load; the
  release that carries this spec drops it.
- **The version stamp**: DuckDB-wasm refuses an extension stamped with another version (`v2.0.0`, not
  `d54cbbe3df`). A shallow submodule has no tag, so a local build and CI's wasm job pass
  `OVERRIDE_GIT_DESCRIBE` (CI reads it from `distribution.yml`'s `duckdb_version`).

## Enforcement & security

- No TLS of tresor's own in wasm: the browser's, through DuckDB-wasm's `XMLHttpRequest`, as already in specs/020.
- The token rules hold as in specs/020: the page's refresh token is a prepared statement's parameter in production
  (the test inlines the fake's), lives in the worker's memory, and goes only to its issuer.

## Testing

- **`scripts/ci/wasm_imports.py <extension> <engine>`**: every symbol the extension imports from `env` (or
  `GOT.*`) is exported by the engine or by the extension itself (emscripten imports a side module's own symbols
  too). Before: 132 unresolved (OpenSSL, `getaddrinfo`, `getnameinfo`); after: none, as DuckDB's own `icu` and
  `excel` for `wasm_eh`.
- **`scripts/ci/test_wasm.sh`** + `test/wasm/shell.mjs` (Playwright, Chromium):
  - DuckDB-wasm's shell from duckdb-wasm's `gh-pages` at a pinned commit (the shell on DuckDB v2.0.0, `wasm_eh`;
    its `?allowUnsignedExtensions=true`), and the extension, both served by the fake service under `/web/` (a new
    `--web-dir`): one origin, so the fake needs no CORS;
  - the imports checked against that engine, then through the shell's worker: `LOAD`, `tresor_version()`, the
    client `duckdb`, the keychain `memory`, `tresor_web_login` with the fake IdP's refresh token, `ATTACH`, `whoami`
    (`alice`, `remembered`), `corp.secrets()`, the secrets in `duckdb_secrets()`, `corp.variable('lake_bucket')`,
    `tresor_login` refused, `DETACH`;
  - the worker answers in its own wire format: an error is a first byte of 1 (a length, the message); a value is
    asked for between markers and found as text.
- **CI**: a `wasm` job builds `wasm_eh` with emsdk 6.0.9 (extension-ci-tools' version) and runs both.
  `wasm_mvp` and `wasm_threads` are built by `distribution.yml` (and were built locally).
- duckdb-ext-common: `OIDC_NO_BUILTIN=1 scripts/test_oidc.sh` (its spec 018).

## Alternatives considered

- **Keep OpenSSL in wasm** (built for emscripten, linked statically): megabytes for a TLS the browser does anyway,
  and httplib's sockets would still not resolve.
- **Build DuckDB-wasm ourselves for the test**: the shell's published build is DuckDB-wasm's own, at DuckDB v2.0.0;
  the npm package on 2.0 is not published yet.

## Follow-ups

- **The token from the page without a second login** (the owner's scenario, next): the page hands tresor an access
  token for tresor's audience and a new one on each renewal - no shared refresh chain. Its own spec, after the
  owner's approval.
- The helper `@hugr-lab/tresor-web` in a browser, once `@duckdb/duckdb-wasm` on 2.0 is on npm.
- DuckDB's `HTTPUtil` has no PATCH: `annotate_*` stay unavailable in wasm (specs/020).
- `description.yml`: drop `excluded_platforms` with the next release.
