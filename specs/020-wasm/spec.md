# Spec 020: tresor in a web application - DuckDB-wasm, the page's login, `attachTresor`

- **Status**: tresor's side and the helper (`web/`) implemented and tested natively and in Node; a browser run
  waits for duckdb-wasm on DuckDB v2.0
- **Date**: 2026-10-05
- **Author**: hugr lab

## Summary

A web application runs DuckDB in the browser (DuckDB-wasm) and its users are already logged in to the
organisation's identity provider. tresor in wasm must attach the secrets service **as that user**, with
nothing for the user to do. After that it works as in the CLI: `corp.secrets()`, `corp.whoami()`,
variables, and secrets in DuckDB's lookup.

- **The page logs in, not tresor.** A small JS helper, `attachTresor`, that we ship does four things:
  - it reads the service's discovery;
  - it logs the user in, asking nothing while the IdP session exists;
  - it loads tresor from a repository, checking its signature;
  - it hands the refresh token to tresor and ATTACHes.
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

An npm package (`@hugr-lab/tresor-web`, in `web/`), plain TypeScript. It depends on an OIDC library
(`oidc-client-ts`); DuckDB-wasm is a peer, used structurally (`connect`, `registerFileBuffer`, `query`,
`prepare`; checked against `@duckdb/duckdb-wasm`'s types). It answers `"attached"`, or `"redirecting"` when the
page is being sent to the IdP: the page calls it on every load, and on its return from the IdP the call finishes.
One call per service and catalog at a time: a second one (React's StrictMode, a double click) shares the first's
outcome rather than use the IdP's answer twice.

The order is chosen so that a code is exchanged while it lives (a minute), nothing is downloaded on the way out,
and nothing reaches tresor before its signature is checked:

1. **Read the service's discovery** with `fetch` (no redirect): `<https://host[/base]>/.well-known/duckdb-secrets`,
   its `protocol` (`duckdb-secrets/1`), `api` and the issuer, with ATTACH's rules - https, http only for a
   loopback service (`127.0.0.1`, `::1`, `localhost`: tresor's own list) with `insecureHttp`; with several
   issuers an `issuer` option names one, as in the CLI.
2. **Log in** with `oidc-client-ts`'s `OidcClient`:
   - authorization code with PKCE, back to the page (or a `redirectUri`); the IdP's session makes the round
     trip ask nothing;
   - the client is the discovery's people's client, which must allow the page (a SPA / public client): the
     remembered login is keyed by it, and tresor renews as it;
   - on the page's return (the redirect URI's path, with `state` and a `code` or an `error`) the code is
     exchanged at once; the answer leaves the URL whatever came of it, so a reload starts a new login; an
     IdP's error is said as such;
   - otherwise the page is sent to the IdP (`location.assign`; nothing awaits the navigation);
   - no token is stored: only the PKCE state is (the page's storage, as oidc-client-ts keeps it).
3. **Load tresor** (`from`, optional; without it tresor must already be loaded).
   - Once duckdb-wasm supports DuckDB v2.0's external repositories
     ([duckdb-wasm#2262](https://github.com/duckdb/duckdb-wasm/issues/2262)), this step is
     `CREATE EXTENSION REPOSITORY … FROM '<from>'` and `LOAD tresor FROM …`.
   - Until then, the helper does the same itself:
     - it fetches `<from>/<revision>/<platform>/tresor.duckdb_extension.wasm`, taking them from the running
       DuckDB (`pragma_version()`: a version without `-dev` is a release, its tag the directory, else the
       source id; `pragma_platform()`), or `revision` / `platform` options (a duckdb-wasm build may name its
       directory otherwise: `DUCKDB_WASM_VERSION`);
     - it verifies the signature with WebCrypto, as DuckDB does: SHA-256 of each 1 MiB chunk, SHA-256 of
       their concatenation, RSA-2048 PKCS#1 v1.5 over the last 256 bytes;
     - DuckDB-wasm's `LOAD` fetches the library by its name (an `XMLHttpRequest` in the worker,
       `extension_load_dynamic.cpp`) and dlopens what that answers; so the name is an **object URL of the
       verified bytes**, `blob:…#/tresor.duckdb_extension.wasm` (the request ignores the fragment, DuckDB
       takes the extension's name from it), registered with `registerFileBuffer` for DuckDB's own reads.
       What is loaded is what was verified. To be proven in the browser run.
     - https only (http for a loopback repository with `insecureHttp`); the file may be redirected to (a
       CDN): the signature, not the URL, is what is trusted.
   - **The keys.** DuckDB pins a repository's keys once, at `CREATE EXTENSION REPOSITORY`. A page has
     nothing to pin them in but its own code: `publicKey` (one or several, PEM - several blocks in one
     string too - or compact) is that, and the production mode. Without it the keys are read from
     `<from>/.well-known/duckdb-extension-repo.json` (no redirect) on every use: trust on each use, which
     guards against a file changed apart from its repository, not against the repository's origin.
   - **Caveat.** DuckDB-wasm itself checks signatures against core keys only, so for now it runs with
     `allowUnsignedExtensions` and the helper's check is the only one. The external-repository support
     removes this caveat.
4. **Hand the login to tresor**: a prepared statement, the token a parameter, so it is never part of a
   statement's text (nor of DuckDB's query log):
   `FROM tresor_web_login(?, ?, issuer := ?, insecure_http := ?)` with `'tresor:host'`, the refresh token,
   the chosen issuer and `insecureHttp` (the ATTACH that follows names the same `ISSUER`).
   - tresor reads the discovery and picks the issuer as the ATTACH would (`issuer`, `insecure_http` as
     ATTACH's options), and stores the refresh token as a **remembered login** (specs/012) under (issuer,
     client_id, service), in the **`memory`** keychain only. It answers that key, and audits a `login`
     (detail `web_login`), never the token.
   - Until the ATTACH's whoami names the person, the entry's subject is `tresor_web_login`, which no
     real subject is: a session already attached under that key never adopts it, and its own rotated
     token replaces only its own person's entry (or a missing one) - never one handed over since.
   - Only the refresh token is handed over: the ATTACH renews it once, which also proves it.
   - It is never a DuckDB secret: `duckdb_secrets()` does not list it, and nothing is written anywhere.
   - Refused: with `tresor_keychain` other than `memory` (the wasm default is `memory`), an empty token, and
     under a duckdb-acl session (no session's user plants a login for the node's people).
   - Compiled natively too: the tests use it, and so may a host that embeds DuckDB and logs in itself.
5. **`ATTACH '<path>' AS <as>`**. tresor finds the remembered login and renews it with the refresh token
   at the IdP's token endpoint, as a remembered login does natively; whoami then stores it again under
   the person's subject.
   - When the refresh token itself has expired (Entra SPA: 24 h), the wasm build fails with "a new login
     to … is needed - … hand it over with tresor_web_login", and the page calls the helper again: a new
     login (asking nothing while the IdP session lives), handed over. In wasm any failed renewal at ATTACH counts as a dead token (forgotten,
     a new login asked): duckdb-wasm's client drops the body of an IdP's `400 invalid_grant`.

### tresor in wasm

- **HTTP through DuckDB.** duckdb-ext-common v0.10.0 (its spec 013) lets a consumer carry the OIDC core's
  requests; tresor's every request - discovery, the IdP's, the service's - goes through one transport.
  - `tresor_http_client`: `builtin` (the OIDC core's own client and tresor's OpenSSL; the native
    default) or `duckdb` (DuckDB's `HTTPUtil`; the only one in wasm, where duckdb-wasm implements it
    over the browser's `XMLHttpRequest` and the TLS is the browser's). The default may come from
    `TRESOR_HTTP_CLIENT`. ATTACH fixes it for the attachment, renewals included; `tresor_logoff` and
    `tresor_web_login` use the current one.
  - DuckDB's transport (`src/tresor_http.cpp`) builds its parameters through an **allow-list opener**,
    which hands DuckDB's client neither the instance nor a connection. So:
    - no `http` secret (a bearer token, extra headers) and no `extra_http_headers` is mixed into a request
      to the IdP or the service, and no logger (DuckDB's HTTP log writes the headers, `Authorization`
      included);
    - certificates are **always verified** (`enable_server_cert_verification`, and curl's, answered
      true, whatever the instance says), against `ca_cert_file` when set;
    - **no redirect** followed, **no retry** (tresor's own rules apply);
    - DuckDB's `http_proxy` is **not** used, as by the built-in client;
    - it sends `User-Agent: tresor/<version> (duckdb)`;
    - a failure is an error with status 0, which the OIDC core redacts.

    The settings are given before the parameters are built: httpfs pins the transport settings it saw
    then, and refuses a request whose settings changed since.
  - The transport refers to the instance without owning it: sessions (and the actor's workers) live in
    an attached catalog, which the instance destroys before anything a request uses.
  - Natively, DuckDB's own client is GET-only: `duckdb` needs httpfs, loaded under the instance's
    autoload settings, or refused at ATTACH ("needs httpfs").
  - `HTTPUtil` has **no PATCH** (`annotate_secret`, `annotate_variable`). Natively it goes through the
    built-in client (the transport calling back into the OIDC core reaches it); in wasm annotating is
    unavailable until DuckDB's `HTTPUtil` gains PATCH.
- **What the wasm build leaves out:**
  - the people's login flows (browser, device): refused with "a new login is needed", the page logs in;
  - `private_key_jwt`: the OIDC core signs with OpenSSL, which the wasm build does not link;
  - the acl actor and `act_for_sessions`: refused before any thread starts, as there is no acl;
  - the OS keychain: `tresor_keychain` defaults to `memory`;
  - the audit's delivery thread: it starts only with a sink (acl-otel), which a page never has; the
    audit goes to DuckDB's log.
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

- **Tokens.** The refresh token passes from the page to tresor as a prepared statement's parameter in the
  same worker: never in a statement's text, so no query log holds it; it reaches no secret and no storage. The refresh token lives in the worker's memory, as an SPA library keeps
  it, and it is gone with the tab.
- **The extension's integrity.** It is verified against the repository's keys by the helper now, and by
  DuckDB itself once external repositories work in duckdb-wasm.
- **Login directly with the IdP, never through the service**: the page talks to the IdP, the service
  only receives bearer tokens. This is the rule as in the CLI.
- **The wasm build has no acl**, so a page cannot act for other users' sessions.

### duckdb-wasm's HTTP client, as it is on 1.x

Read from duckdb-wasm `lib/src/http_wasm.cc`, to check again on its 2.0 port and raise upstream if still so:
- `XMLHttpRequest` follows redirects and cannot be told not to: the "no redirect" rule holds natively only.
- A POST's body is kept for a 2xx answer only: an IdP's `400 invalid_grant` arrives without its body, so a
  dead refresh token reads as a failed renewal rather than as `invalid_grant` (either way a new login).
- A successful PUT answers the `ETag` in place of the body; tresor reads only the status of a PUT.

## Testing

- **The wasm build compiles** (`make wasm_eh`, no `GEN=ninja`, emsdk 3.1.71: `tresor.duckdb_extension.wasm`,
  0.9 MB). It stays out of the CI pipeline until duckdb-wasm is on v2.0.
- **DuckDB's client, natively, in CI**: the whole attach suite runs twice, on the built-in client and with
  `TRESOR_HTTP_CLIENT=duckdb` (`scripts/ci/test_attach.sh` loads httpfs in each test's database).
- `test/sql/http_client.test`: the setting's values, and `duckdb` refused without httpfs.
- `test/sql/http_client.test`: also a `tresor_logoff` on a `duckdb` client that cannot be had (no
  httpfs) - it still forgets.
- `test/sql/attach/web_login.test`: the refusals (keychain not memory, NULL, empty, a scheme, an acl
  session); the hand-over, then an ATTACH with no browser and exactly one refresh, `whoami().login =
  'remembered'`; a second hand-over replacing the entry the ATTACH stored, by a prepared statement as
  the helper calls it; a token the IdP does not know (forgotten, a new login).
- `test/sql/attach/duckdb_client.test` (both CI runs): on `duckdb`, an `http` secret with a bearer token
  and extra headers for the service's host reaches neither the IdP nor the service (the fake counts
  them), a dead `http_proxy` changes nothing, and the discovery is asked by `tresor/…`; on `builtin`,
  by another agent.
- Not tested yet: https on DuckDB's client (the fake and the Keycloak run are plain http on loopback),
  and a `307` not followed (curl's and httplib's `follow_location` off, read from httpfs).
- The reference server's `cors_origins`: config refusals (a wildcard, a path, http off loopback), and the
  answers (preflight, an allowed and another origin, none configured).
- **Runtime, later:**
  - a DuckDB-wasm we build at our pin;
  - an example app (`examples/web/`: Vite, `@duckdb/duckdb-wasm`, the helper);
  - a Playwright test against Keycloak and the reference server with CORS: log in, ATTACH, then
    `whoami()`, `secrets()`, a variable, and a renewal (a short-lived access token renewed by tresor).
- **The helper** (`web/`, `npm test`, CI job "Web helper (node)"):
  - the signature: a file signed by DuckDB's own signing (`duckdb/scripts/compute-extension-hash.sh` +
    `openssl pkeyutl -sign -pkeyopt digest:sha256`) verifies, byte-identical to the helper's notion of
    it; tampered bytes (in each chunk, in the signature), another key, a short file and malformed keys
    are refused;
  - `attachTresor` against stubs of DuckDB-wasm, `fetch` and the login: the order (discovery, the code
    exchanged, the download, LOAD, the hand-over, ATTACH, from an event log); the LOAD's name answering
    exactly the verified bytes, revoked after; the prepared hand-over with the token only a parameter; a
    tampered file loads nothing and hands nothing over; pinned keys (several in one PEM string);
    "redirecting" with nothing downloaded; one call at a time; another protocol; several issuers; the
    transport rules (127.0.0.2 is not loopback); quoting; the revision directory (`-dev`, a release
    candidate);
  - the login: the IdP's answer recognised only at the redirect URI, and removed from the URL even when
    the exchange fails; an issuer without a people's client or the code flow;
  - the types: `AsyncDuckDB` and `AsyncDuckDBConnection` are what `attachTresor` takes;
  - `test/sql/attach/web_login.test` runs the helper's exact prepared statement against tresor.

## Alternatives considered

- **A login inside tresor in wasm** (popup, device flow, two steps with a pasted code). It is either
  impossible from a worker or a burden on the user.
- **An access token only, as a `tresor` secret.** It fails after the token's lifetime, and it is a
  secret in DuckDB's storage.
- **Porting tresor to duckdb-wasm's 1.x DuckDB.** tresor uses v2.0's API throughout: `Identifier`,
  function signatures, the table-function bind, `HTTPUtil`, external repositories.

## Follow-ups

- **duckdb-wasm#2262**: external repositories in duckdb-wasm, which retires the helper's own loading.
- **duckdb-ext-common**: a pluggable HTTP transport for `oidc/` (its spec 013) - done, v0.10.0.
- **DuckDB**: a PATCH request type in `HTTPUtil` (annotating from wasm).
- **duckdb-wasm**: redirects not followed on request, and a POST's error body kept (above).
- **A docs page**, "tresor in a web application": the contract above, plus IdP setup (Keycloak, Entra
  SPA).
