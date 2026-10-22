---
sidebar_position: 3.7
title: In a web application
---

# tresor in a web application

A web application runs DuckDB in the browser (DuckDB-wasm), and its users are already logged in to the
organisation's identity provider. tresor attaches the secrets service **as that user**, with nothing
for them to do. After that it works as in the CLI: `corp.secrets()`, `corp.whoami()`, variables, and
the secrets in DuckDB's lookup.

There are two ways to hand the user's login to tresor:

- **The application's own login** (recommended when the application logs its users in already - an SPA with
  oidc-client-ts or MSAL): it hands tresor the **access token** it holds for the secrets service's audience, and a new
  one each time it renews its own. No second login, no redirect, and the application's refresh token never leaves
  it. [The application's token](#the-applications-token).
- **The helper's login**: `attachTresor` logs the user in itself, as the service's people's client, and tresor renews
  the login from the refresh token. [The page](#the-page).

:::note In a browser
tresor's wasm build loads in DuckDB-wasm on DuckDB v2.0. CI runs it in a browser, in DuckDB-wasm's own shell (the
build behind shell.duckdb.org): the page's login handed over with `tresor_web_login`, or its token with
`tresor_web_token`, `ATTACH`, `whoami`, the secrets, a variable. Still to come:
- the npm package `@duckdb/duckdb-wasm` on DuckDB 2.0, which a page builds on (not published yet);
- the helper `@hugr-lab/tresor-web`, tested in Node so far;
:::

## The application's token

The application logs the user in with its identity provider, as it does already, and asks for a token the secrets
service accepts: its `aud` must be the `audience` of the service's discovery.

- **Keycloak**: an *audience* mapper on the application's client (or a client scope it requests) adds the service's
  audience to the application's own access token - one token serves both.
- **Microsoft Entra ID**: a token has one audience. The application asks for a second one, silently, with the
  service's scope (MSAL `acquireTokenSilent({ scopes: ["api://duckdb-secrets/access_as_user"] })`). The service's
  API registration issues v2.0 tokens (`accessTokenAcceptedVersion: 2`, as the [Entra setup](entra.md) has it): a
  v1.0 token's issuer (`sts.windows.net`) is not the discovery's, and tresor refuses it.

Then:

```js
import { attachTresor } from "@hugr-lab/tresor-web";

const user = await userManager.getUser();          // oidc-client-ts: the application's login
await attachTresor(db, "tresor:secrets.corp.example", {
  as: "corp",
  from: "https://ext.corp.example",
  publicKey: "-----BEGIN PUBLIC KEY-----…",
  token: user.access_token,                        // or a function returning it
  // each renewed token, handed over; the attached catalog takes it at its next query
  onTokenChange: (push) => {
    const on = (u) => push(u.access_token);
    userManager.events.addUserLoaded(on);
    return () => userManager.events.removeUserLoaded(on);
  },
  signal: controller.signal,                       // ends the subscription
});
```

Without the helper, the same in SQL - the token a prepared statement's parameter, never in a statement's text:

```sql
FROM tresor_web_token($1, $2);        -- 'tresor:secrets.corp.example', the access token; again on each renewal
ATTACH 'tresor:secrets.corp.example' AS corp;
```

- tresor keeps the token in this instance's memory only, one per service (and issuer). Each call of the attached
  catalog uses the newest; tresor never renews it and never sees the application's refresh token.
- A token that says it is for another audience, from another issuer, or already expired, is refused at
  `tresor_web_token` and never sent. An opaque token is taken as the application's word.
- When the token expires (or the service refuses it) and no new one was handed over, queries fail with *the
  page's token … has expired or was refused - the page hands over a new one*. With oidc-client-ts's automatic silent
  renewal and `onTokenChange`, that does not happen while the application's own login lives.
- **Another user, or a token that does not say whose it is** (an opaque one): the catalog asks the service who it is
  before going on, and everything held for the previous user goes - nothing of one user is served to the next.
- The application logs its user out: `FROM tresor_logoff('corp')` forgets the token and empties the catalog of
  everything held for that login (and detaches; `detach := false` keeps the catalog until the next token).
  `tresor_logoff()` forgets every page token. Stop `onTokenChange` (its `signal`) too: a token pushed after the
  logoff logs the catalog in again. A logoff by service, issuer and client id concerns remembered logins only.
- A failed push (an expired token, one refused) rejects its promise and is reported to `onTokenError` (else
  `console.error`).
- `whoami().login` is `page`.

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
| `FROM tresor_web_token(service, access_token [, issuer := …, insecure_http := …])` | The application's access token for the service, handed over - and again on each renewal: kept in this instance's memory, the newest used by every call of a catalog attached on it. Never under a duckdb-acl session. Returns `service`, `issuer`, `expires_at`. |
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
