---
sidebar_position: 3.7
title: In a web application
---

# tresor in a web application

A web application runs DuckDB in the browser (DuckDB-wasm), and its users are already logged in to the
organisation's identity provider. tresor attaches the secrets service **as that user**, with nothing
for them to do. After that it works as in the CLI: `corp.secrets()`, `corp.whoami()`, variables, and
the secrets in DuckDB's lookup. tresor renews the login itself.

:::caution Not yet in a browser
Everything below is implemented and tested in Node and natively. A browser needs DuckDB-wasm on
DuckDB v2.0, which tresor is built for
([duckdb-wasm#2262](https://github.com/duckdb/duckdb-wasm/issues/2262)). Until then this page is the
contract, not a recipe that runs.
:::

## The page

The page logs in, not tresor: a DuckDB-wasm worker opens no window and listens on no port. The
helper `@hugr-lab/tresor-web` (not yet published; built from `web/`) does the rest.

```js
import * as duckdb from "@duckdb/duckdb-wasm";
import { attachTresor } from "@hugr-lab/tresor-web";

const db = new duckdb.AsyncDuckDB(logger, worker);
await db.instantiate(bundle.mainModule);
// until duckdb-wasm checks a repository's keys itself (duckdb-wasm#2262), the helper's check is the only one
await db.open({ allowUnsignedExtensions: true });

// on every load of the page: it comes back here from the IdP, and this call finishes the login
const outcome = await attachTresor(db, "tresor:secrets.corp.example", {
  as: "corp",
  from: "https://ext.corp.example",                // the extension repository
  publicKey: "-----BEGIN PUBLIC KEY-----…",         // its signing key, pinned in the page
});
if (outcome === "attached") {
  const conn = await db.connect();
  await conn.query("FROM corp.secrets()");
}
// "redirecting": the page is being sent to the identity provider
```

`attachTresor`, in this order:

1. **Reads the service's discovery** and picks the issuer as `ATTACH` would. With several issuers,
   `issuer` names one.
2. **Logs the person in** with the identity provider directly: authorization code with PKCE, back to
   the page (or `redirectUri`). While the IdP's session lives, the round trip asks nothing. No token
   is stored by the page.
3. **Loads tresor** from `from`, its signature verified exactly as DuckDB verifies one, against
   `publicKey`. Without `publicKey`, against the keys the repository publishes at
   `<from>/.well-known/duckdb-extension-repo.json`: that trusts the repository's origin on every use, so
   pin the key in production. An unverified file is not loaded. Until duckdb-wasm supports DuckDB
   v2.0's external repositories, the page's DuckDB-wasm runs with `allowUnsignedExtensions`, and this
   check is the only one.
4. **Hands the login to tresor** with `tresor_web_login`, the refresh token a prepared statement's
   parameter: never in a statement's text, nor in DuckDB's query log.
5. **`ATTACH`es.** tresor renews the access token from the refresh token, as it renews a remembered
   login.

A login lives as long as the tab: every load of the page logs in anew (asking nothing while the IdP's
session lives). When the refresh token expires while the page is open (Entra: 24 hours), queries on
`corp` fail with *the login … is over - a new login is needed*: `DETACH corp` and call `attachTresor`
again.

## tresor's side

| | |
| --- | --- |
| `tresor_http_client` | `duckdb` in wasm (the only client there): DuckDB's HTTP client, the browser's underneath. Natively `builtin` (the default) or `duckdb` (httpfs). |
| `FROM tresor_web_login(service, refresh_token [, issuer := …, insecure_http := …])` | A login made elsewhere, handed over: remembered in this instance's memory for the next `ATTACH`. Only with `tresor_keychain = 'memory'` (the wasm default), and never under a duckdb-acl session. |
| `tresor_keychain` | `memory` in wasm: a tab has no credential store, and the login lives as long as the tab. |

Not in wasm: the browser and device logins (the page logs in), service identities with a private
key, acting for duckdb-acl's sessions, and `annotate_secret` / `annotate_variable` (DuckDB's HTTP
client has no `PATCH` yet).

## The identity provider

The page's login uses the discovery's **people's client** - the one the CLI logs in with - so the
remembered login and its renewals stay one client's. That client must also allow the page.

The redirect URI is matched exactly: register the URL `attachTresor` returns to - the page's own,
without its query, unless `redirectUri` names one fixed page (an application with client-side routes
should).

### Keycloak

On the people's client (a public client, *Client authentication* off):

| Setting | Value |
| --- | --- |
| Standard flow | on (authorization code) |
| Advanced → Proof Key for Code Exchange Code Challenge Method | `S256` (what the helper sends) |
| Valid redirect URIs | the page's URL, e.g. `https://app.corp.example/analytics` |
| Web origins | the page's origin, `https://app.corp.example` (CORS on the token endpoint) |
| Advanced → Use refresh tokens | on (the default); with `offline_access` in the discovery's scopes, the client keeps the `offline_access` optional scope (the default) |

### Microsoft Entra ID

On the people's app registration ([Entra ID](entra.md#2-peoples-client)), next to its *Mobile and
desktop* platform:

| Setting | Where | Value |
| --- | --- | --- |
| Redirect URI | Authentication → Add a platform → **Single-page application** | the page's URL |

- A *Single-page application* redirect URI makes Entra answer the token endpoint with CORS, and issue
  refresh tokens that live **24 hours** and are redeemed only by cross-origin requests (with an
  `Origin` header). tresor in wasm makes exactly those (from the page's worker), so the renewals
  work; a native tresor cannot redeem them, and logs in itself as usual.
- The scopes are the discovery's (`openid offline_access api://duckdb-secrets/access_as_user`), consented
  as for the CLI.

## The secrets service

Its API is called from the page's worker, so it answers CORS for the page's origin
([protocol: Browsers](protocol.md#conventions)). The reference server:

```yaml
cors_origins: [https://app.corp.example]   # as a browser sends it: lower case, no default port
```

Every origin is listed exactly - no wildcard. The page sends a bearer token, never a cookie.
