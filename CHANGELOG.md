# Changelog

All notable changes to tresor are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each entry names the spec it comes from
(`specs/NNN`).

## [Unreleased]

### Added

- **windows_arm64**: built and tested by the distribution workflow, and opted into in the community descriptor.
- **`ASSERTION_TYPE`** on a `federated` service login: `'jwt-spiffe'` sends the `ASSERTION_FILE` (a SPIFFE
  JWT-SVID) as Keycloak's SPIFFE client authentication takes it; `'jwt-bearer'` is the default, as before.
  Needs duckdb-ext-common spec 019 (`ClientAuth::assertion_type`). A pipelines page section on SPIFFE; the spike
  in `examples/spiffe-spike` (specs/046).

## [0.1.1] - 2026-10-25

The docs, reviewed before publishing; no change to the extension's code.

### Added

- **An SQL reference** (`reference`): every ATTACH option with its default, the `tresor` secret's options per
  `FLOW`, the settings and their environment defaults, every function with its columns, and the audit's columns,
  kinds, outcomes and reason codes.
- **In your application** (`embedding`, in the sidebar now): tresor from Python, Go, Rust, Java and .NET, and the
  application's own login; a JDBC example.
- **Development**: the wasm builds, the web helper's tests, and building tresor into another extension.

### Fixed

- The docs' sidebar lists every page (In your application, the SQL reference, the reference server); tresor-server
  in the navbar and footer, its docs linked where the pages describe what it implements (references, generated
  values, token exchange, variables).
- The protocol page's examples agree with its text: `capabilities.write` / `annotate` are informational, and
  whoami's `permissions.create` example is a boolean.
- The reference server's page: tresor-server is released; the conformance suite's requirements and variables.
- Smaller corrections: `LOGIN 'auto'` over SSH, `requestedAccessTokenVersion`, `FROM tresor_logoff()` throughout.
- The community-extensions descriptor: a fuller description, the website link, the version 0.1.1.

## [0.1.0] - 2026-10-22

The first release, with DuckDB 2.0.0. The protocol `duckdb-secrets/1` is version 1, normative from here on.

### Added

- **Attach a secrets service** with `ATTACH 'tresor:<host>' AS corp`. DuckDB loads the installed
  extension by the prefix. The ATTACH covers discovery, the login and the mount (specs/001, 002).
- **People log in** through the browser (authorization code with PKCE, loopback redirect) or the
  device flow (with PKCE where the issuer advertises it, as a Keycloak that enforces it needs), directly with the
  identity provider (specs/002, 040). `whoami` names the person: a `name` column (specs/041).
- **Services log in** with a `tresor` secret, by its `FLOW` (specs/002, 013, 015):
  - `client_credentials`: a client secret, or a private key (`private_key_jwt`, RS256/ES256, `x5t`);
  - `federated`: a token from a file, from GitHub Actions, or from the Azure managed identity;
  - `managed_identity`: Azure's, with no credential at all;
  - `token`: a token already held.
- **Auth0**: the discovery may ask clients to send `audience` (specs/013).
- **Generated variables**: a variable's value may carry an `expires_at` (a value the service generates per
  read, such as a MotherDuck token); tresor caches it until shortly before it (specs/037).
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
- **The application's own login** (specs/043): an application that logs its users in - a web page, or any program
  that embeds DuckDB (Python, Go, Rust, Java; .NET with DuckDB.NET on 2.0) - hands tresor its access token for the service, and each renewed one,
  with `tresor_web_token`: no second login, and its refresh token never leaves it. `whoami().login` is `page`;
  another user's token empties the catalog of the previous one's; `attachTresor` takes `token`, `onTokenChange`.
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
- **Platforms**: Linux, macOS and Windows (clang-cl with `/GF-`, specs/022), and wasm (`wasm_eh`, `wasm_mvp`,
  `wasm_threads`): no OpenSSL or sockets of its own, every request through DuckDB's client - the browser's; it loads
  in DuckDB-wasm on DuckDB 2.0, run in CI in a browser in DuckDB-wasm's own shell (specs/042, duckdb-ext-common
  spec 018); `wasm_threads` linked with shared memory, which DuckDB's pipeline leaves out (specs/044).
- **Built for DuckDB 2.0.0** (the `v2.0.0` tag, duckdb-ext-common v0.15.0), together with duckdb-acl and
  acl-otel (specs/014, 019, 021, 023, 028, 031, 034, 038).
- **Docs**, Microsoft Entra ID included: <https://hugr-lab.github.io/tresor/>.
- **Pipelines** in the docs: a job logs in as a service identity, a recipe per executor (Kubernetes,
  GitHub Actions, Azure, a key, a client secret, a token) and dbt-duckdb's profile (specs/026).

[Unreleased]: https://github.com/hugr-lab/tresor/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/hugr-lab/tresor/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/hugr-lab/tresor/releases/tag/v0.1.0
