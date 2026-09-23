# Spec 004: the secret storage — the service's secrets in DuckDB's lookup, `corp.secrets()`

- **Status**: implemented
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

`TresorSecretStorage : SecretStorage`, named after the catalog:
- `persistent = true` (writes are spec 005);
- a tie-break offset of `40 + n`, below 100 and unique per instance (duckdb requires uniqueness). It
  ranks the service after duckdb's own storages (0/5/10/20) when scores are equal: a lower offset
  wins.

**Registration and lifetime.** duckdb has no API to remove a storage.
- **Registered before any login.** The storage is registered, inactive, at the first ATTACH of a
  name. duckdb's own storages are loaded first (a secret-manager call forces its lazy
  initialization). A name duckdb already uses (`local_file`, `connection`, ...) is therefore refused
  before a browser ever opens. Registering first would break duckdb's own initialization until
  restart.
- **Activated by the catalog.** `TresorCatalog::Initialize` activates the storage with the session
  and the descriptor list the ATTACH fetched. A service that cannot list its secrets is not attached.
- **Deactivated with the catalog.** `OnDetach` or the catalog's destructor deactivates it: an ATTACH
  that is rolled back, or fails after the storage callback, leaves nothing in the lookup. A
  deactivation only takes effect if its session is still the one served.
- The registry of tresor's storages lives in the instance's `ObjectCache`, so it dies with the
  instance.

**What each call does:**
- **`LookupSecret(path, type)`**:
  1. Take the descriptors of `type` whose `permissions` include `use`.
  2. Score them with duckdb's own rule (`SelectBestMatch`).
  3. Fetch the best one's material.

  If the service answers 404 or 403 for it now, there is no match and the list is marked stale.
  The fetch happens even when another storage later wins (the cost of one cached fetch).
- **`GetSecretByName(name)`** fetches material only for a listed name with `use`. A name without
  `use` is not found here, so it never shadows a local secret of that name with an error. A local
  secret with the same name as a usable service secret is duckdb's "ambiguous" error, which is
  documented.
- **`AllSecrets()`** (`duckdb_secrets()`) returns descriptors only and never throws.
- **Service secrets of type `tresor`** are shown by `corp.secrets()` but never take part in the
  lookup, the listing or name lookups. tresor's own login search walks every storage, and a
  service must not plant another ATTACH's login.
- **`StoreSecret` / `DropSecretByName`** answer "not supported yet (specs/005)".

### Descriptors and material

- The descriptor list (`GET /v1/secrets`) is cached for **30 s**. One refresh runs at a time,
  outside the state lock; a lookup arriving meanwhile uses the list it has. A failed refresh keeps
  **the last list authoritative for matching** and is not retried for 5 s.
  - **Fail closed, but only where the service would decide.** A path the service's secrets cover
    fails at the material fetch, naming the service and the secret. A path they do not cover is not
    this storage's business: `duckdb_secrets()`, other paths and local secrets keep working.
  - The network calls themselves (list, material) are bounded by the transport's timeout. A lookup
    that needs the network cannot be interrupted until then.
- Material (`GET /v1/secrets/{name}`) is cached per name and version, and expired entries are
  evicted at every fetch.
  - A static secret's material is kept until the descriptor's `version` changes or 5 minutes pass.
  - A dynamic secret's material is kept until shortly before its `expires_at`: 30 s, or half its
    remaining life if that is shorter, so a short-lived credential is not minted anew for every file
    of a scan.
  - A dynamic secret without a readable expiry is never reused.
- Material becomes a `KeyValueSecret`:
  - `scope`, `type`, `provider` and `name` come from the descriptor;
  - each param becomes a DuckDB `Value` (below);
  - `redact_keys` come from the service. A fixed conservative set (`secret`, `password`, `token`,
    `session_token`, `private_key`, `client_secret`, `bearer_token`, `access_token`,
    `account_key`, `connection_string`) is always added, when present, as a net under a service that
    forgets them.
- Typed values (protocol, *Material*):
  - A bare string is `VARCHAR`. Any other bare value is an error, not a silent NULL.
  - `{type, value}` parses `type` with DuckDB's type parser; without a connection (a background
    lookup), only simple types parse.
  - Scalars are cast from their JSON text, and numbers are read raw, so a `HUGEINT` or `DECIMAL`
    keeps every digit. `BLOB` is the VARCHAR→BLOB cast's escaped text.
  - `LIST` and fixed-size `ARRAY` come from an array. `STRUCT` comes from an object whose field
    names compare case-insensitively: an unknown field is an error, a missing one is NULL.
    `MAP(K, V)` comes from an object, keys cast to `K`. `null` is NULL.
  - A value that does not fit its type is an error naming the secret, the key and the type. It never
    quotes the value, and never includes a cast message that would.
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
- A lookup fails closed where the service's secrets decide, and nowhere else.
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
    secret, so tresor registers a diagnostic, `tresor_secret_param(name, key)`:
    - it returns the value with its type (`INTEGER 1433`), through `GetSecretByName`;
    - a redacted key shows its type only (`VARCHAR <redacted>`);
    - it is **refused unless `allow_unredacted_secrets`** is on. duckdb lets that setting be turned
      off at runtime but not back on;
  - HUGEINT and DECIMAL(38,2) keeping every digit; a bare non-string parameter is refused;
  - a value that does not fit its type: the error names the secret and key, never the value;
  - a secret without `use` never matching;
  - `DETACH` removing the secrets from the lookup, and re-ATTACH bringing them back;
  - the material fetched once while cached;
  - a service whose material is down: its covered path fails closed, while an uncovered path,
    `duckdb_secrets()` and dropping a local secret keep working;
  - a service that cannot list its secrets is not attached;
  - a rolled-back ATTACH leaving nothing in the lookup;
  - `local_file` / `connection` refused before any login, including as the very first secret
    operation (`test/sql/attach_storage_names.test`), with the secret manager intact afterwards;
  - a service's `tresor`-typed secret neither listed in `duckdb_secrets()` nor disturbing the next
    ATTACH's login;
  - a dynamic secret cached for half its life, and one already expired never reused;
  - `DROP PERSISTENT SECRET … FROM corp` answering "not supported yet (specs/005)".
- A test that a local secret wins a tie against the service needs a local secret of a type the test
  shell has (s3 needs httpfs, which the shell does not load). It waits for spec 005's writes, which
  bring a `tresor`-typed round trip.
- **The conformance suite** gains `secrets.test`. The service's operator seeds a secret and names it
  in `TRESOR_CONFORMANCE_SECRET` (+ `_TYPE`, `_PATH`, `_KEY`, `_VALUE`). The test finds it in
  `svc.secrets()` with `use`, through `which_secret` in the service's storage, and reads its
  parameter. `scripts/ci/test_keycloak.sh` seeds one in the reference server through the protocol,
  as the `etl` service.

## The review's findings (applied)

An independent review, most of them reproduced against the fake:

- **A cast error quoted the value** ("Could not convert string 'not-a-number'"). It now names the
  secret, key and type only, and a test asserts the value is absent.
- **One unreachable service broke secret operations instance-wide**: `duckdb_secrets()`, `DROP
  SECRET` of a local secret, lookups of unrelated types, and the next ATTACH. Now the last list stays
  authoritative, and only a path the service covers fails.
- **A rolled-back ATTACH left its secrets and live tokens in the lookup.** Activation moved to the
  catalog's `Initialize`; deactivation happens in its destructor too.
- **`ATTACH … AS local_file` as the first secret operation broke the secret manager until restart.**
  duckdb's storages are now forced to load first, and taken names are refused before the login.
- **The lock was held across network calls.** Refreshes are now single-flight outside the lock,
  with a failure backoff.
- **A service could plant a `tresor` login for another ATTACH.** Such secrets are excluded from the
  lookup.
- **Name lookups of secrets without `use` threw "see but not use"**, shadowing local secrets. They
  are now not found.
- **A material 404/403 after the list failed the query.** It is now no match, and the list is marked
  stale.
- **`FromJson`:** raw numbers (HUGEINT, DECIMAL), bare non-strings refused, case-insensitive STRUCT
  fields with unknown ones refused, and ARRAY support.
- **`tresor_secret_param`** no longer shows redacted keys' values.
- **Lower findings:** expired material evicted; dynamic margins at most half the life; a dynamic
  secret without an expiry never reused; offsets capped below 100; the always-redacted set widened;
  the protocol page keeps only the normative sentence about caching.

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
