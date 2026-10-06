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
- **Single sign-on**: a person's refresh token is kept in the OS credential store (macOS
  Keychain, Windows Credential Manager, the Secret Service), per service; `tresor_logoff()` (specs/012).
- **The service's secrets join DuckDB's lookup**: `corp.secrets()`, `corp.whoami()`, `which_secret`,
  material fetched on use and cached (specs/004).
- **Writes and grants**: `CREATE / DROP PERSISTENT SECRET … IN corp`, `annotate_secret`, `grants`,
  `grant_secret`, `revoke_secret`. Administrators manage; roles use (specs/005, 009).
- **Dynamic secrets**: a token minted for the caller, and httpfs's `REFRESH auto` through the
  `tresor` provider (specs/006, 010).
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
- **Audit and traces**: every login, lookup, write and grant as a typed event, for DuckDB's log and
  for OpenTelemetry through acl-otel (`tresor_audit_level`, TRSA 1) (specs/011).
- **The protocol `duckdb-secrets/1`** (draft until this release), a reference server in Go and a
  conformance suite (specs/003, 016).
- **Docs**, Microsoft Entra ID included: <https://hugr-lab.github.io/tresor/>.
