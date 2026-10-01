# tresor

**One OIDC login, role-based secrets for DuckDB.** tresor attaches your organisation's secrets
service: log in once through your identity provider (Keycloak, Okta, Entra ID, any OIDC provider)
and the secrets your role may use join DuckDB's own secret lookup.

```sql
ATTACH 'tresor:secrets.corp.example' AS corp;          -- browser login, once

FROM corp.secrets();                                   -- what your role may use
ATTACH '' AS crm (TYPE mssql, SECRET crm_ro);          -- a secret from the service
FROM 's3://lake/sales/*.parquet';                      -- found by scope, like any secret
CREATE PERSISTENT SECRET lake_rw IN corp (TYPE s3, …); -- stored in the service, if your role may
```

- **A client, not a vault** — the service is anything implementing the open protocol
  [`duckdb-secrets/1`](website/docs/protocol.md); how it stores secrets is its own business.
- **The ATTACH is the whole setup** — DuckDB loads the installed extension by the `tresor:` prefix;
  discovery, login and mounting happen inside the ATTACH.
- **Your role decides** what you may use; administrators manage secrets and grant their use to roles
  — through the CLI, or through a server acting for you, which serves you its own grants.

**Status: complete for its first release, which ships with DuckDB 2.0.** It covers:
- people's and services' logins: browser and device flows, keys, federated tokens, managed identities;
- single sign-on through the OS keychain;
- the service's secrets in DuckDB's lookup, writes and grants;
- dynamic secrets;
- acting for [duckdb-acl](https://github.com/hugr-lab/duckdb-acl)'s sessions;
- an audit for DuckDB's log and OpenTelemetry.

Until the release, build it from source (below). See the [CHANGELOG](CHANGELOG.md), the design
([specs/001](specs/001-architecture/spec.md)) and the docs (<https://hugr-lab.github.io/tresor/>).
A production service: [tresor-server](https://github.com/hugr-lab/tresor-server).

## Building

```bash
git clone --recurse-submodules https://github.com/hugr-lab/tresor.git
cd tresor
make vcpkg-setup          # once: OpenSSL (or VCPKG_TOOLCHAIN_PATH=<a vcpkg>/scripts/buildsystems/vcpkg.cmake)
GEN=ninja make
build/release/test/unittest 'test/sql/*'
scripts/ci/smoke_load.sh
```

The full test setup (the fake service, Keycloak, duckdb-acl) is on the
[Development](https://hugr-lab.github.io/tresor/development/) page.

tresor tracks the DuckDB 2.0 line at the same commit as
[duckdb-acl](https://github.com/hugr-lab/duckdb-acl).

## License

MIT — see [LICENSE](LICENSE).
