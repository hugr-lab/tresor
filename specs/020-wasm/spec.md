# Spec 020: tresor in a web application - DuckDB-wasm, the page's login, `attachTresor`

- **Status**: draft (implemented outside the release pipeline until duckdb-wasm moves to DuckDB v2.0)
- **Date**: 2026-10-05
- **Author**: hugr lab

## Summary

A web application runs DuckDB in the browser (DuckDB-wasm) and its users are already logged in to the
organisation's identity provider. tresor in wasm must attach the secrets service **as that user**, with
nothing for the user to do. After that it works as in the CLI: `corp.secrets()`, `corp.whoami()`,
variables, and secrets in DuckDB's lookup.

- **The page logs in, not tresor.** A small JS helper, `attachTresor`, that we ship does four things:
  - it loads tresor from a repository, checking its signature;
  - it reads the service's discovery;
  - it logs the user in, silently when the IdP session exists;
  - it hands the tokens to tresor and ATTACHes.
- **tresor renews the login itself.** It holds the refresh token in memory, as a remembered login
  (specs/012), so the access token's 15 minutes are not the limit.

```js
await attachTresor(db, 'tresor:secrets.corp.example', {
  as: 'corp',
  from: 'https://ext.hugr-lab.example',   // the extension repository; its keys from .well-known
  // publicKey: '-----BEGIN PUBLIC KEY-----…',  // optional: pin the signing key instead
});
// then, as in the CLI:
await conn.query("FROM corp.secrets()");
```

## Problem

- **The CLI's logins cannot run in a browser.** DuckDB-wasm runs in a Web Worker:
  - a worker opens no window;
  - nothing can listen on a loopback port for the redirect;
  - an `ATTACH` blocks the worker, so no message from the page reaches it meanwhile;
  - the IdP's session cookie is the browser's, not the worker's.
- **tresor's own HTTP client needs sockets and OpenSSL.** It compiles for wasm, but a browser has no
  sockets: emscripten turns them into WebSockets to a proxy.
- **tresor's threads** (the acl actor's workers, the audit's background delivery) do not exist in
  `wasm_mvp`/`wasm_eh`.
- **A login that only hands over an access token** fails after the token's lifetime.

## Design

### The helper: `attachTresor(db, path, options)`

An npm package (`@hugr-lab/tresor-web`), plain TypeScript. It depends on `@duckdb/duckdb-wasm` and on an
OIDC library (`oidc-client-ts`).

1. **Load tresor** (`from`, optional; without it tresor must already be loaded).
   - Once duckdb-wasm supports DuckDB v2.0's external repositories
     ([duckdb-wasm#2262](https://github.com/duckdb/duckdb-wasm/issues/2262)), this step is
     `CREATE EXTENSION REPOSITORY … FROM '<from>'` and `LOAD tresor FROM …`.
   - Until then, the helper does the same itself:
     - it fetches `<from>/<duckdb version>/<platform>/tresor.duckdb_extension.wasm`, taking the version and
       platform from the running DuckDB;
     - it verifies the signature with WebCrypto, as DuckDB does: SHA-256 of each 1 MiB chunk, SHA-256 of
       their concatenation, RSA-2048 PKCS#1 v1.5 over the last 256 bytes;
     - the keys are `<from>/.well-known/duckdb-extension-repo.json`'s `signature_keys`, or `publicKey`
       when given (pinned);
     - it then `registerFileBuffer`s the verified bytes and `LOAD`s them.
   - **Caveat.** DuckDB-wasm itself checks signatures against core keys only, so for now it runs with
     `allowUnsignedExtensions` and the helper's check is the trust anchor. The external-repository support
     removes this caveat.
2. **Read the service's discovery** with `fetch`: `<https://host[/base]>/.well-known/duckdb-secrets`, giving
   the issuer, the people's `client_id`, the `scopes` and the `audience`. With several issuers, an
   `issuer` option names one, as in the CLI.
3. **Log in** with `oidc-client-ts`:
   - authorization code with PKCE, redirect back to the page;
   - the IdP's session makes it silent;
   - the client is the discovery's (a SPA client), or a `clientId` option;
   - the redirect is the page's own, or a `redirectUri` option.
4. **Hand the tokens to tresor**: `CALL tresor_web_login('tresor:host', access_token, refresh_token,
   expires_at)`.
   - This is a function compiled into the wasm build only.
   - It puts the refresh token into the `memory` keychain, under the key of specs/012 (issuer,
     client_id, service), as a remembered login. The access token is kept as that login's current one.
   - It is never a DuckDB secret: `duckdb_secrets()` does not list it, and nothing is written anywhere.
5. **`ATTACH '<path>' AS <as>`**. tresor finds the remembered login and renews it with the refresh token
   at the IdP's token endpoint, as a remembered login does natively.
   - When the refresh token itself has expired (Entra SPA: 24 h), tresor fails with "a new login is
     needed", and the helper repeats step 3 (silent while the IdP session lives).

### tresor in wasm

- **HTTP through DuckDB**: `HTTPUtil`/`HTTPTransportManager`, which in wasm is httpfs over the browser's
  `fetch`. duckdb-ext-common's `oidc::HttpSend` gets a pluggable transport (its own spec), and the wasm
  build uses DuckDB's. There are no sockets and no OpenSSL, and the TLS is the browser's. httpfs is a
  dependency of the wasm build only; the native build keeps its own client.
- **What the wasm build leaves out:**
  - the people's login flows (browser, device): the page logs in;
  - `private_key_jwt`, federated and managed identity: they make no sense in a browser;
  - the acl actor and `act_for_sessions`;
  - the OS keychain: `tresor_keychain` is `memory`;
  - the audit's background thread: delivery is synchronous.
- **What it keeps:**
  - the protocol client (whoami, secrets, writes, grants, variables, dynamic material);
  - the remembered-login renewal;
  - the audit (to DuckDB's log);
  - `tresor_web_login`.
- **Crypto**: renewing a login needs none. If anything needs SHA-256, it is DuckDB's mbedtls.

### What the environment provides

- **The IdP**: a SPA client with refresh tokens, and CORS for the page's origin on discovery and the token
  endpoint.
  - Keycloak: a public client with Web Origins.
  - Entra: the SPA platform (refresh tokens of 24 h).
- **The secrets service**: CORS for the page's origin. `protocol.md` gains a short *Browsers* note: a
  service meant for browsers SHOULD answer CORS, including on its discovery, and allow the
  `Authorization`, `Delegation` and `If-*` headers. The reference server gets `cors_origins`.
- **DuckDB-wasm on v2.0**, the same commit tresor is built for, as any loadable extension requires.

## Enforcement & security

- **Tokens.** They pass from the page to tresor through one SQL call in the same worker, and reach no
  log, no secret and no storage. The refresh token lives in the worker's memory, as an SPA library keeps
  it, and it is gone with the tab.
- **The extension's integrity.** It is verified against the repository's keys by the helper now, and by
  DuckDB itself once external repositories work in duckdb-wasm.
- **Login directly with the IdP, never through the service**: the page talks to the IdP, the service
  only receives bearer tokens. This is the rule as in the CLI.
- **The wasm build has no acl**, so a page cannot act for other users' sessions.

## Testing

- **The wasm build compiles today** (`make wasm_eh` at duckdb eb0d9df: `tresor.duckdb_extension.wasm`,
  1.1 MB). It stays out of the CI pipeline until duckdb-wasm is on v2.0.
- **Runtime:**
  - a DuckDB-wasm we build at our pin;
  - an example app (`examples/web/`: Vite, `@duckdb/duckdb-wasm`, the helper);
  - a Playwright test against Keycloak and the reference server with CORS: log in, ATTACH, then
    `whoami()`, `secrets()`, a variable, and a renewal (a short-lived access token renewed by tresor).
- **The helper's signature check:** a unit test with a signed and a tampered file.

## Alternatives considered

- **A login inside tresor in wasm** (popup, device flow, two steps with a pasted code). It is either
  impossible from a worker or a burden on the user.
- **An access token only, as a `tresor` secret.** It fails after the token's lifetime, and it is a
  secret in DuckDB's storage.
- **Porting tresor to duckdb-wasm's 1.x DuckDB.** tresor uses v2.0's API throughout: `Identifier`,
  function signatures, the table-function bind, `HTTPUtil`, external repositories.

## Follow-ups

- **duckdb-wasm#2262**: external repositories in duckdb-wasm, which retires the helper's own loading.
- **duckdb-ext-common**: a pluggable HTTP transport for `oidc/` (its spec).
- **A docs page**, "tresor in a web application": the contract above, plus IdP setup (Keycloak, Entra
  SPA).
