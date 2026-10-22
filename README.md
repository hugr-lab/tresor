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

**Status: released - 0.1.0, for DuckDB 2.0.0.** It covers:
- people's and services' logins: browser and device flows, keys, federated tokens, managed identities;
- logging in from DuckDB UI, notebooks and IDEs (`tresor_login`), and pipelines as service identities;
- single sign-on through the OS keychain, `tresor_logoff` to forget it;
- the service's secrets in DuckDB's lookup, writes and grants, and its optional variables;
- dynamic secrets: any parameter generated per caller;
- acting for [duckdb-acl](https://github.com/hugr-lab/duckdb-acl)'s sessions;
- an audit for DuckDB's log and OpenTelemetry.

A web application's path - the page's login handed over (`tresor_web_login`, on DuckDB's HTTP client) and
the helper `@hugr-lab/tresor-web`: tresor's wasm build loads in DuckDB-wasm on DuckDB 2.0, proven in a browser in
CI (specs/042).

Install it from DuckDB's community extensions (`INSTALL tresor FROM community;`, DuckDB 2.0), or build it
from source (below). See the [CHANGELOG](CHANGELOG.md), the design
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

tresor is built for DuckDB 2.0 (the `v2.0.0` tag) at the same commit as
[duckdb-acl](https://github.com/hugr-lab/duckdb-acl).

## License

MIT — see [LICENSE](LICENSE).
