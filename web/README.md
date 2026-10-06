# @hugr-lab/tresor-web

`attachTresor`: tresor in a web application's DuckDB-wasm, attached as the person logged in to the
organisation's identity provider (tresor [specs/020](../specs/020-wasm/spec.md)).

```js
import * as duckdb from "@duckdb/duckdb-wasm";
import { attachTresor } from "@hugr-lab/tresor-web";

const db = new duckdb.AsyncDuckDB(logger, worker);   // DuckDB-wasm on DuckDB v2.0
await db.instantiate(bundle.mainModule);

// on every load of the page - it comes back here from the IdP, and this call finishes the login
const outcome = await attachTresor(db, "tresor:secrets.corp.example", {
  as: "corp",
  from: "https://ext.hugr-lab.example",              // the extension repository
  publicKey: "-----BEGIN PUBLIC KEY-----…",           // its signing key, pinned in the page
});
if (outcome === "attached") {
  const conn = await db.connect();
  await conn.query("FROM corp.secrets()");           // then, as in the CLI
}
// "redirecting": the page is being sent to the IdP
```

What it does, in this order:

1. **Reads the service's discovery** and picks the issuer as `ATTACH` would (`issuer` with several):
   https, and http only for a loopback service with `insecureHttp`.
2. **Logs the person in** with the IdP directly (oidc-client-ts, authorization code with PKCE, the
   discovery's people's client, back to the page). On the page's return the code is exchanged at once;
   the answer is removed from the URL whatever came of it. With the IdP's session alive the round trip
   asks nothing. Tokens are never stored - only the PKCE state is, as oidc-client-ts keeps it.
3. **Loads tresor** from `from`: `<from>/<revision>/<platform>/tresor.duckdb_extension.wasm`, its
   signature verified with WebCrypto exactly as DuckDB verifies it. DuckDB-wasm's `LOAD` fetches the
   library by its name, so the name is an object URL of the verified bytes: what is loaded is what was
   verified. An unverified file is not loaded, and nothing is handed to it.
4. **Hands the login to tresor**: `FROM tresor_web_login(?, ?, issuer := ?, insecure_http := ?)`, the
   refresh token a prepared statement's parameter - never in a statement's text.
5. **`ATTACH`es.** tresor renews the login itself from then on.

One call at a time per service and catalog: a second call while one runs shares its outcome.

## Trusting the extension

DuckDB pins a repository's keys once, at `CREATE EXTENSION REPOSITORY`. A page has nothing to pin them
in but its own code: **`publicKey`** (one or several, PEM or compact) is that, and the production mode.
Without it the keys are read from `<from>/.well-known/duckdb-extension-repo.json` (no redirect) on every
use: the check then guards against a file changed apart from its repository (a CDN, a cache), not
against the repository's origin itself.

Until duckdb-wasm supports DuckDB v2.0's external repositories
([duckdb-wasm#2262](https://github.com/duckdb/duckdb-wasm/issues/2262)), the page's DuckDB-wasm runs
with `allowUnsignedExtensions`, and this check is the only one.

## The environment

- The IdP's people's client allows the page: a SPA / public client with refresh tokens, the page as a
  redirect URI, CORS for the page's origin.
- The secrets service answers CORS for the page (the reference server's `cors_origins`).
- DuckDB-wasm at the DuckDB commit tresor was built for. A duckdb-wasm build may name its extension
  directory otherwise than `pragma_version()` says: `revision` (and `platform`) override.
- TypeScript users: 5.7 or later (the typings use `Uint8Array<ArrayBuffer>`).

## Status

Tested in Node: the signature against DuckDB's own signing, `attachTresor` against stubs of
DuckDB-wasm, `fetch` and the login, and the types against `@duckdb/duckdb-wasm`'s. Not yet run in a
browser - that waits for duckdb-wasm on DuckDB v2.0; the object-URL `LOAD` above is to be proven there.

```sh
npm ci && npm test    # needs the duckdb submodule (its signing script)
```
