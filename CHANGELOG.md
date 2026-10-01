# Changelog

All notable changes to tresor are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Each entry names the spec it comes from
(`specs/NNN`).

## [Unreleased] - the first release, with DuckDB 2.0

### Added

- **Attach a secrets service** with `ATTACH 'tresor:<host>' AS corp`. DuckDB loads the installed
  extension by the prefix. The ATTACH covers discovery, the login and the mount (specs/001, 002).
- **People log in** through the browser (authorization code with PKCE, loopback redirect) or the
  device flow, directly with the identity provider (specs/002).
- **Services log in** with a `tresor` secret (specs/002, 013, 015):
  - client credentials with a secret, a private key (`private_key_jwt`, RS256/ES256, `x5t`) or a
    federated token (a file, GitHub Actions, or the Azure managed identity);
  - Azure managed identity;
  - a token.
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
- **Audit and traces**: every login, lookup, write and grant as a typed event, for DuckDB's log and
  for OpenTelemetry through acl-otel (`tresor_audit_level`, TRSA 1) (specs/011).
- **The protocol `duckdb-secrets/1`** (draft until this release), a reference server in Go and a
  conformance suite (specs/003, 016).
- **Docs**, Microsoft Entra ID included: <https://hugr-lab.github.io/tresor/>.
