# Spec 004: the secret storage — the service's secrets in DuckDB's lookup, `corp.secrets()`

- **Status**: draft
- **Date**: 2026-09-23
- **Author**: VGSML (with Claude)

## Summary

After spec 004, `ATTACH 'tresor:<host>' AS corp` does what tresor exists for. The secrets the
caller's role may use take part in DuckDB's own secret lookup, so `FROM 's3://lake/…'`, `ATTACH …
(SECRET crm_ro)` and `which_secret(…)` find them like any other secret. The attach registers a
**secret storage** named after the catalog. It lists descriptors (no material) from the service,
matches scopes locally, and fetches material only for the secret a lookup actually picks.
`corp.secrets()` shows what the caller may see and what they may do with each secret. This spec
covers reading; writes (`CREATE PERSISTENT SECRET … IN corp`) are spec 005.

## Problem

After spec 002 a person or a service can log in, but DuckDB still cannot use a single secret from
the service. That is the whole point of attaching it.

## Design

### The storage

`TresorSecretStorage : SecretStorage`, registered with `SecretManager::LoadSecretStorage` at the
first ATTACH of a name:
- `name` = the catalog's name;
- `persistent = true` (writes are spec 005);
- a tie-break offset of `40 + n`, unique per instance (duckdb requires it), which ranks the service
  after duckdb's own storages when scores are equal.

duckdb has **no API to remove a storage**:
- `DETACH` deactivates it: no session, `IncludeInLookups() = false`, empty answers.
- A later `ATTACH` of the same name reactivates the same storage with the new session.
- The registry of tresor's storages lives in the instance's `ObjectCache`, so it dies with the
  instance.

- **`LookupSecret(path, type)`**:
  1. Take the descriptors of `type` whose `permissions` include `use`.
  2. Score them with duckdb's own rule (`BaseSecret::MatchScore`, longest scope prefix, through
     `SelectBestMatch`).
  3. Fetch the material of the best one and return it.

  The fetch happens even when another storage later wins with a higher score (the cost of one
  cached fetch). A secret without `use` never matches: the service would refuse its material, and
  a lookup must not fail on a secret the caller cannot use.
- **`GetSecretByName(name)`** fetches the material when the name is listed with `use`. It returns
  nothing when the name is not listed, and an error when it is listed without `use` ("you may see
  it, not use it").
- **`AllSecrets()`** (`duckdb_secrets()`) returns every listed secret **without material**: its
  name, type, provider and scope. Listing never fetches material.
- **`StoreSecret` / `DropSecretByName`** answer "not supported yet (specs/005)".

### Descriptors and material

- The descriptor list (`GET /v1/secrets`) is cached for **30 s**. A lookup that finds the cache
  stale refreshes it. When the service cannot be reached and no list was ever fetched, the lookup
  **fails** with the service's name: a missing credential must not silently become an anonymous
  request. When a stale list exists and the refresh fails, the stale list serves for up to 5 more
  minutes.
- Material (`GET /v1/secrets/{name}`) is cached per name and version. A static secret's material is
  kept until the descriptor's `version` changes or 5 minutes pass. A dynamic secret's material is
  kept until 30 s before its `expires_at`.
- Material becomes a `KeyValueSecret`:
  - `scope`, `type`, `provider` and `name` come from the descriptor;
  - each param becomes a DuckDB `Value` (below);
  - `redact_keys` come from the service. A fixed conservative set (`secret`, `password`, `token`,
    `session_token`, `private_key`, `client_secret`, `bearer_token`, `access_token`) is always
    added, when present, as a net under a service that forgets them.
- Typed values (protocol, *Material*):
  - A bare string is `VARCHAR`.
  - `{type, value}` parses `type` with DuckDB's type parser.
  - Scalars are cast from their JSON text.
  - `LIST` comes from an array, `STRUCT` from an object by field name, and `MAP(K, V)` from an
    object, keys cast to `K`.
  - A value that does not fit its type is an error naming the secret and the key, never the value.
- Nothing from the material is written to disk or logged.

### `corp.secrets()`

One row per descriptor, in the service's order:
- `name`, `type`, `provider`, `scope VARCHAR[]`, `comment`, `owner`;
- `permissions VARCHAR[]`, `dynamic BOOLEAN`, `updated_at TIMESTAMPTZ`, `version VARCHAR`.

It always fetches a fresh list (and refreshes the cache), so a user sees the service's current
state.

### Protocol

No change to requests or responses. The protocol page gains one sentence under *Secrets*: a client
fetches material only for a secret its lookup picked, and lists without material.

## Enforcement & security

- Material only on a match, only for secrets holding `use`, and only in memory, with bounded cache
  lifetimes. `DETACH` drops the caches together with the session.
- A lookup fails closed when the service has never answered.
- `duckdb_secrets()` shows descriptors only. `allow_unredacted_secrets` has nothing to reveal for
  them. A matched secret's material is redacted by the keys the service names.

## Testing

- **The fake** (`test/fake/fake_service.py`) serves secrets:
  - a list with scopes and permissions, and material with typed values (VARCHAR, INTEGER, BOOLEAN,
    MAP, STRUCT, LIST);
  - a secret without `use`, and a dynamic secret;
  - counters that let a test see how often material was fetched.
- `test/sql/attach/secrets.test`:
  - `which_secret` for a matching and a non-matching path, and the type filter;
  - the longest scope winning, and a secret without `use` falling back to the next scope;
  - `corp.secrets()` columns;
  - `duckdb_secrets()` without material;
  - the typed values arriving as DuckDB types. duckdb has no function that shows one parameter of a
    secret, so tresor registers `tresor_secret_param(name, key)`. It returns the value with its type
    (`INTEGER 1433`) through `GetSecretByName`. It is **refused unless `allow_unredacted_secrets`**
    is on, the same gate as `duckdb_secrets(redact := false)`. duckdb lets that setting be turned
    off at runtime but not back on, so a locked server can never re-enable it;
  - a value that does not fit its type: the error names the secret and key, never the value;
  - a secret without `use` never matching;
  - `DETACH` removing the secrets from the lookup, and re-ATTACH bringing them back;
  - the material fetched once while cached;
  - lookups failing closed against a service that is down;
  - `DROP PERSISTENT SECRET … FROM corp` answering "not supported yet (specs/005)".
- A test that a local secret wins a tie against the service needs a local secret of a type the test
  shell has (s3 needs httpfs, which the shell does not load). It waits for spec 005's writes, which
  bring a `tresor`-typed round trip.
- **The conformance suite** gains `secrets.test`. The service's operator seeds a secret and names it
  in `TRESOR_CONFORMANCE_SECRET` (+ `_TYPE`, `_PATH`, `_KEY`, `_VALUE`). The test finds it in
  `svc.secrets()` with `use`, through `which_secret` in the service's storage, and reads its
  parameter. `scripts/ci/test_keycloak.sh` seeds one in the reference server through the protocol,
  as the `etl` service.

## Alternatives considered

- **Fetching all material at ATTACH.** It would reach the laptop for every secret the role may
  use, including ones this session never needs, and dynamic ones would expire unused.
- **A storage per connection.** duckdb's secret storages are per instance. The session is
  per-catalog, shared by the instance's connections, as spec 002 decided.
- **Registering the storage with the lowest tie-break.** A local secret with an equal score should
  win: it is the user's explicit override on their own machine.

## Follow-ups

- spec 005: `CREATE / DROP PERSISTENT SECRET … IN corp`, `annotate_secret`, grants.
- spec 006: dynamic secrets and the `REFRESH auto` provider for httpfs.
