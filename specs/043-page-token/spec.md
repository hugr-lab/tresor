# Spec 043: the application's own login - its access token handed over (`tresor_web_token`)

- **Status**: implemented
- **Date**: 2026-10-22
- **Author**: hugr lab (the owner's scenario through the duckdb-acl session, approved 2026-10-22: tresor in a
  DuckDB-wasm another web application embeds, with no second login)

## Summary

A web application that logs its users in already (an SPA with oidc-client-ts or MSAL) embeds DuckDB-wasm with tresor.
For the user tresor must be transparent: no second login, no redirect of tresor's own. The application hands tresor
the **access token** it holds for the secrets service's audience - `FROM tresor_web_token(service, ?)`, a prepared
statement's parameter - and a new one each time it renews its own login. tresor keeps it in memory, attaches on it,
and every call uses the newest. tresor never renews it and never sees the application's refresh token. The helper
`attachTresor` gains `token`, `onTokenChange` and `signal`.

## Problem

- `attachTresor` (specs/020) logs the user in itself as the service's people's client: a second login (silent while
  the IdP's session lives, but a redirect), with a client the application does not own.
- Handing tresor the application's refresh token (`tresor_web_login`) would put one rotating refresh chain in two
  holders: whichever renews first invalidates the other's token.
- `FLOW 'token'` (a tresor secret) takes no new token: it says "replace the secret and ATTACH again" when it expires,
  and its token is part of a `CREATE SECRET` statement's text.

## Design

- **`FROM tresor_web_token(service, access_token [, issuer := …, insecure_http := …])`**:
  - discovery and the issuer as `ATTACH` would choose them (ATTACH's rules: no scheme, `insecure_http` for loopback);
  - a JWT is read, unverified, to refuse sending it where it is not meant to go: an `iss` other than the issuer, an
    `aud` without the discovery's `audience`, or an `exp` past - refused, never kept. An opaque token is taken as
    the application's word (no expiry known);
  - kept in the instance's memory (`PageTokens`, an object-cache entry), one per (issuer, service); a newer one
    replaces it. Never a file, never the OS store;
  - returns `service`, `issuer`, `expires_at` (NULL for an opaque token); audited as a `login` with detail
    `web_token`, never the token;
  - refused under a duckdb-acl session (an acl user must not plant a login for the node's people), with NULL or empty
    arguments.
- **`ATTACH`**: a person's ATTACH (no service secret, no `LOGIN`) whose service and issuer have a page token attaches
  on it: login flow **`page`** (`whoami().login`), nothing remembered, no login of tresor's own. Without one, as before
  (natively the person's login; in wasm "the page hands over its access token with tresor_web_token").
- **Every call** of a `page` session reads the newest token (a lookup in memory): a token handed over after the ATTACH
  is used from the next call. A token past its `exp`, or one the service refused (401), is not sent again: "the
  page's token … has expired or was refused - the page hands over a new one".
- **`tresor_logoff`**: `tresor_logoff('corp')` on a `page` catalog forgets its service's token (and detaches, unless
  `detach := false` - then the catalog waits for the page's next token); `tresor_logoff()` forgets every page token.
  Nothing is revoked: the refresh chain is the application's. A `page` session whose token was forgotten says
  "logged off … the page hands over a token".
- **The helper** (`web/`): `token` (a string, or a function of one), `onTokenChange(push)` (the helper subscribes
  after the ATTACH; `push` hands a token over on a connection of its own; the subscription's unsubscribe runs when
  `signal` aborts). With `token` the helper neither logs in nor redirects.
- **No protocol change**: the service receives a bearer token as from any client.

## Enforcement & security

- An IdP token goes only to its audience: tresor sends the page's token only to the service it was handed over for,
  and refuses a JWT that names another audience or issuer. The service verifies the token as always.
- The token is a prepared statement's parameter: never in a statement's text or the query log; wiped when replaced or
  forgotten.
- The application's refresh token never reaches tresor: no shared rotating chain.
- No new trust in the service: login stays directly with the IdP (the application's own login); the service is never
  asked to exchange the application's token (that would hand it a token not meant for it).

## Testing

- `test/sql/attach/web_token.test` (both HTTP clients): refusals (NULL, empty, a scheme, another audience, another
  issuer, expired, an acl session); the hand-over as the helper prepares it, `ATTACH` with no authorize and no
  refresh at the IdP, `whoami` (`page`, the person), the secrets, a variable; a refused token, then a new one taken by
  the same session; an opaque token; a token expiring with none newer; `tresor_logoff('corp', detach := false)`
  (logged off, then resumed by a new token); `tresor_logoff()`; an ATTACH with nothing handed over logs the person in.
  The fake's `/_page_token` mints the person's token with the claims asked (`aud`, `iss`, `ttl`, `opaque`,
  `unknown`).
- `test/wasm/shell.mjs` (in a browser, specs/042): the page's token handed over, ATTACH, `whoami` `page`, the secrets,
  a renewed token taken at the next call.
- `web/test/attach.test.ts`: the token handed over as a parameter with no login or redirect, a token function, an
  empty token refused before loading, each pushed token handed over until the signal aborts.

## Alternatives considered

- **Token exchange at the service**: the application's token would go to the service, which is not its audience,
  and the service would log in on the user's behalf - against "login directly with the IdP".
- **The application's refresh token to tresor** (`tresor_web_login`): one rotating chain in two holders.
- **A callback from the worker to the page for each token**: a DuckDB call cannot wait for the page from inside the
  worker; pushing on each renewal is simpler and needs nothing from DuckDB-wasm.

## Follow-ups

- The helper in a browser once `@duckdb/duckdb-wasm` on 2.0 is on npm (or on hugr-platform's build).
