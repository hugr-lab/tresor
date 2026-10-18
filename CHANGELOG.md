# Changelog

All notable changes to tresor are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each entry names the spec it comes from
(`specs/NNN`).

## [Unreleased]

The first release, with DuckDB 2.0.

### Added

- **Attach a secrets service** with `ATTACH 'tresor:<host>' AS corp`. DuckDB loads the installed
  extension by the prefix. The ATTACH covers discovery, the login and the mount (specs/001, 002).
- **People log in** through the browser (authorization code with PKCE, loopback redirect) or the
  device flow, directly with the identity provider (specs/002).
- **Services log in** with a `tresor` secret, by its `FLOW` (specs/002, 013, 015):
  - `client_credentials`: a client secret, or a private key (`private_key_jwt`, RS256/ES256, `x5t`);
  - `federated`: a token from a file, from GitHub Actions, or from the Azure managed identity;
  - `managed_identity`: Azure's, with no credential at all;
  - `token`: a token already held.
- **Auth0**: the discovery may ask clients to send `audience` (specs/013).
- **DuckDB's sandbox**: `enable_external_access = false` stops tresor's requests on either client unless
  `allowed_directories` / `allowed_paths` name their URL (specs/036).
- **Single sign-on**: a person's refresh token is kept in the OS credential store (macOS
  Keychain, Windows Credential Manager, the Secret Service), per service; `tresor_logoff()` (specs/012).
- **The service's secrets join DuckDB's lookup**: `corp.secrets()`, `corp.whoami()`, `which_secret`,
  material fetched on use and cached (specs/004).
- **Writes and grants**: `CREATE / DROP PERSISTENT SECRET … IN corp`, `annotate_secret`, `grants`,
  `grant_secret`, `revoke_secret`. Administrators manage; roles use (specs/005, 009).
- **Dynamic secrets**: a token minted for the caller, and httpfs's `REFRESH auto` through the
  `tresor` provider (specs/006, 010). Any parameter of any secret type may be generated per caller, the
  descriptor carrying the consumer's provider and every generated key in `redact_keys`; the reference server
  generates `mint+exchange://<audience>` (a token) and `mint+claim://<claim>` (a claim of the caller's token),
  `provider: token_exchange` staying an alias (specs/029).
- **A served secret is of its type's own class**: a type an extension registers with a class of its own
  (BigQuery's `BigquerySecret`) reaches the extension in that class, through the type's deserializer, as a
  secret read from a file would; tested with a stub type of its own class (specs/032).
- **Checked with the extensions that consume the secrets**: httpfs (s3, http), postgres_scanner and iceberg
  use what tresor serves - a request signed with the served key, a database login as the served user
  (specs/033).
- **Acting for duckdb-acl's sessions**:
  - `ACT_FOR_SESSIONS` at ATTACH, or `corp.act_for_sessions()` later;
  - a session's user token exchanged (RFC 8693 or Entra On-Behalf-Of) for a delegation grant,
    revoked when the session ends (specs/008, 015).
- **Variables**, optional in the protocol (`capabilities.variables`): named strings a service holds,
  read with `corp.variable(name[, fallback])`, listed with `corp.variables()`, managed with
  `set_variable` and its siblings. A value may be a reference the service resolves. Such a value is
  `sensitive` and is handled as secret material (specs/018).
- **Toward web applications** (DuckDB-wasm, specs/020): `tresor_http_client` (`builtin`, or `duckdb` -
  DuckDB's HTTP client, the only one in wasm), `tresor_web_login()` (a login the page made, handed over and
  remembered in memory), CORS in the protocol and the reference server (`cors_origins`), and the page's
  helper `@hugr-lab/tresor-web` (`attachTresor`: the extension verified and loaded, the login handed over).
- **Log in from any client** (specs/025): `tresor_login()` answers at once with the link and device code
  (DuckDB UI, notebooks, IDEs) and completes in the background, an ATTACH waiting for it; `tresor_logoff`
  detaches the catalogs on the login (`detach := false` keeps them, taking up the next login); `prompt` to switch
  identity.
- **Pipelines checked live** (specs/027): a managed identity, a managed identity as an app registration's
  federated credential (its v1 token's `aud`, the app id of AzureADTokenExchange, now accepted) and an AKS pod's
  projected token on Azure; a Kubernetes token with Keycloak 26.7+ on kind; the `tresor-live` image.
- **A private CA** (specs/030): DuckDB's `ca_cert_file` is trusted by tresor's built-in client too, beside the
  system's roots - for the ATTACH, a session's calls and renewals, `tresor_login` and `tresor_logoff`.
- **Audit and traces**: every login, lookup, write and grant as a typed event, for DuckDB's log and
  for OpenTelemetry through acl-otel (`tresor_audit_level`, TRSA 1) (specs/011).
- **The protocol `duckdb-secrets/1`** (draft until this release), a reference server in Go and a
  conformance suite (specs/003, 016).
- **Built into another extension** (specs/024): `tresor_sources.cmake` (`TRESOR_EMBEDDED`) and
  `LoadTresorCore`, as hugr-node's `hugr_node` builds tresor in.
- **Platforms**: Linux, macOS and Windows (clang-cl with `/GF-`, specs/022); wasm compiles (specs/020) but is
  not distributed until duckdb-wasm is on DuckDB 2.0.
- **Built for DuckDB 2.0**: the `v2.0-cyanoptera` line (today f8f3f4d, duckdb-ext-common v0.13.0), moved
  together with duckdb-acl and acl-otel; at the release, the `v2.0.0` tag for all three (specs/014, 019, 021,
  023, 028, 031, 034).
- **Docs**, Microsoft Entra ID included: <https://hugr-lab.github.io/tresor/>.
- **Pipelines** in the docs: a job logs in as a service identity, a recipe per executor (Kubernetes,
  GitHub Actions, Azure, a key, a client secret, a token) and dbt-duckdb's profile (specs/026).
