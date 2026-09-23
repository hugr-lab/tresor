# Spec 006: dynamic secrets — the `tresor` provider behind httpfs's `REFRESH auto`

- **Status**: draft
- **Date**: 2026-09-23
- **Author**: VGSML (with Claude)

## Summary

A dynamic secret (`dynamic: true`, material generated per request with an `expires_at`) is what the
security model recommends for people: short-lived, personal credentials. Spec 004 already serves
them from a cache bounded by their expiry. This spec closes the loop for httpfs's S3-family secrets
(`s3`, `r2`, `gcs`). When S3 answers 401/403 mid-query, httpfs's **`REFRESH auto`** re-creates the
secret through its provider. For a service secret that provider is **`tresor`**, which asks the
service for fresh material and never writes anything back.

The spec also removes a hazard that already exists. A service secret carrying httpfs's own
`refresh_info` would be refreshed through its original provider and written back to the service.
For a `credential_chain` secret that would be the *grantee's* locally resolved credentials.

## Problem

- **Expiry mid-scan.** httpfs refreshes a secret only through the provider recorded in it, with the
  options in its `refresh_info`, as `CREATE OR REPLACE SECRET` into the secret's own storage
  (`CreateS3SecretFunctions::TryRefreshS3Secret`). A dynamic credential from the service that
  expires during a long scan fails the query until the cache expires.
- **Write-back.** A static service secret stored with `REFRESH auto` (its `refresh_info` travels as a
  param) would, on a 403, be re-created by `config` or `credential_chain` in the reader's process.
  That means a `PUT` to the service (a write the reader may not hold), or worse, the reader's own
  resolved credentials stored for every grantee.

## Design

### Reading material (spec 004's `MaterialOf`, extended)

- `refresh` and `refresh_info` are **dropped** from every service secret's params. A service secret
  is refreshed only by tresor.
- A **dynamic** secret of type `s3`, `r2` or `gcs` gets:
  - provider `tresor`;
  - `refresh_info = {tresor_service: <storage>, tresor_secret: <name>}`: names only, nothing secret,
    and exactly the options httpfs passes back to the provider.
- Static secrets keep their provider and get no `refresh_info`. When their credential stops working,
  the fix is the service's (rotate), not a refresh.

### The `tresor` provider

`CreateSecretFunction {type: s3 | r2 | gcs, provider: tresor}`, registered at load. duckdb checks the
type only at CREATE, so the load order with httpfs does not matter.
- **Options:** `TRESOR_SERVICE` (an attached tresor catalog) and `TRESOR_SECRET` (the name there).
- **It fetches fresh material:**
  1. it drops the cached material for the name;
  2. it fetches it from the service (`GET /v1/secrets/{name}`);
  3. it returns the secret, shaped as above.
- **Only into its own storage.** The provider accepts nothing but `IN <tresor_service>`. That is
  what httpfs's refresh does (it passes the secret's storage). A `CREATE SECRET … (TYPE s3,
  PROVIDER tresor, …)` into `memory` or `local_file` is refused: service material must not land in
  another storage, least of all on disk.

### Storing a refreshed secret (`StoreSecret`)

- A secret whose provider is `tresor` is a refresh, not a write. It replaces the name's cached
  material and returns its entry. **No request goes to the service.**
- Any other secret is written as spec 005 describes, but `refresh` and `refresh_info` are left out
  of the params. A refresh recipe from the writer's process has no meaning in the service.

### One mint for parallel refreshes

The requests of one scan (HEAD and GET, several files) fail in parallel, and each asks for a
refresh. A mint younger than 2 s answers all of them, instead of each minting another credential.

### Limits

- **Persistent secrets must be allowed.** httpfs's refresh goes through `RegisterSecret`, which
  applies duckdb's persistent-storage rules. With `allow_persistent_secrets = false`, refreshing a
  service secret fails, as every write to the service does. This is documented.
- **The reference server has no dynamic secrets** (`capabilities.dynamic: false`). The path is
  tested against the fake. A dynamic backend in the reference server is a follow-up.

### httpfs in the test build

With httpfs linked, a schemed ATTACH path reaches tresor, which refuses the scheme itself.
`test/sql/tresor.test` accepts either refusal.


`extension_config.cmake` loads httpfs, for the tests only, at the commit and with the patches that
duckdb's own 2.0 tree pins (`duckdb/.github/config/extensions/httpfs.cmake`). Its curl comes from
vcpkg. tresor does not depend on httpfs. With httpfs linked, a schemed ATTACH path reaches tresor,
which refuses the scheme itself; `test/sql/tresor.test` accepts either refusal.

## Enforcement & security

- A refresh never writes to the service and never takes credentials from the reader's environment.
  The service mints, and the client only fetches.
- Service material never leaves the service's storage through the provider.
- `refresh_info` carries names only.

## Testing

- **The fake** grows:
  - a dynamic `s3` secret (`dyn_s3`) whose `key_id` counts its mints (`DYN-S3-n`) and whose
    `endpoint` is the fake itself;
  - a static `s3` secret stored with a `refresh_info` param (`static_with_refresh`);
  - a minimal **S3 endpoint**: HEAD/GET on `/dynbucket/…` answers 403 to the first key it ever sees
    and 200 with content to any other; it reads the key from the SigV4 `Credential=`.
- **`test/sql/attach/refresh.test`** (with httpfs):
  - `read_text('s3://dynbucket/hello.txt')` succeeds through a real 403 → httpfs refresh → the
    `tresor` provider → fresh material → retry;
  - afterwards the material in the lookup is a later mint (not the refused first one);
  - the service received no write;
  - a static service secret carries no `refresh_info` and keeps its provider;
  - the provider is refused into `memory`;
  - an s3 secret written with `REFRESH auto` reaches the service without `refresh_info`.

## Alternatives considered

- **Leaving httpfs's refresh to the original provider.** That is the write-back above.
- **Refusing all refresh for service secrets.** A dynamic secret expiring mid-scan would then fail
  the query. The provider costs one small function.

## Follow-ups

- A dynamic backend in the reference server (an STS-like mint, or a database user per session).
- spec 007: delegation.
