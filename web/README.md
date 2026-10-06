# @hugr-lab/tresor-web

`attachTresor`: tresor in a web application's DuckDB-wasm, attached as the person logged in to the
organisation's identity provider (tresor [specs/020](../specs/020-wasm/spec.md)).

```js
import { attachTresor } from "@hugr-lab/tresor-web";

// on the page's load - and again when the IdP sends the person back to it
const outcome = await attachTresor(db, "tresor:secrets.corp.example", {
  as: "corp",
  from: "https://ext.hugr-lab.example",   // the extension repository; its keys from .well-known
  // publicKey: "-----BEGIN PUBLIC KEY-----…",   // optional: pin the signing key instead
});
if (outcome === "attached") {
  await conn.query("FROM corp.secrets()");  // then, as in the CLI
}
// "redirecting": the page is on its way to the IdP, and comes back to finish
```

What it does:

1. **Loads tresor** from `from`: `<from>/<revision>/<platform>/tresor.duckdb_extension.wasm`, its
   signature verified with WebCrypto exactly as DuckDB verifies it, against the repository's
   `signature_keys` (`<from>/.well-known/duckdb-extension-repo.json`) or a pinned `publicKey`. Nothing
   unverified is loaded, and nobody is logged in for it. Until duckdb-wasm supports DuckDB v2.0's
   external repositories ([duckdb-wasm#2262](https://github.com/duckdb/duckdb-wasm/issues/2262)) the
   page's DuckDB-wasm runs with `allowUnsignedExtensions`, and this check is the trust anchor.
2. **Reads the service's discovery** and picks the issuer as `ATTACH` would (`issuer` with several).
3. **Logs the person in** with the IdP directly (oidc-client-ts, authorization code with PKCE, the
   discovery's people's client): silent while the IdP's session lives. Tokens stay in memory, never in
   the page's storage.
4. **Hands the login to tresor**: `FROM tresor_web_login(?, ?, issuer := ?, insecure_http := ?)`, the
   refresh token a prepared statement's parameter - never in a statement's text.
5. **`ATTACH`es.** tresor renews the login itself from then on.

The environment: the IdP's people's client allows the page (a SPA / public client with refresh tokens,
CORS for the page's origin), and the secrets service answers CORS (the reference server's
`cors_origins`).

```sh
npm ci && npm test    # stubs for DuckDB and the network; the signature against DuckDB's own signing
```
