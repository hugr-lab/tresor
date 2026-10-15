# Spec 032: a served secret of its type's own class - through the type's deserializer

- **Status**: implemented
- **Date**: 2026-10-15
- **Author**: hugr lab
- **Asked by**: tresor-server's check of the extensions' sources (BigQuery); the owner: the universal way, through
  the deserializer

## Summary

tresor builds every secret it serves as a `KeyValueSecret`. An extension that registers its type with a class of
its own casts what a lookup finds to that class: duckdb-bigquery (`1568f8e`) does
`dynamic_cast<const BigquerySecret &>(secret_match.GetSecret())` in its client's options (REST and gRPC), so a
`bigquery` secret from the service fails every ATTACH and scan with `std::bad_cast` - a single person's own DuckDB
too. `BigquerySecret` is a `KeyValueSecret` with no fields of its own: the same `secret_map`, its own redact keys,
a deserializer `KeyValueSecret::Deserialize<BigquerySecret>`.

## Design

- When material is fetched, the secret built from the service's params is read back through the deserializer its
  type registered (`SecretType::deserializer`, found among `SecretManager::AllSecretTypes()` - never autoloading
  an extension): serialized as a key-value secret into memory, then deserialized as `SecretManager::DeserializeSecret`
  does after the type's header (fields 100-103), by the type's own function. It is what DuckDB does with a
  persistent secret read from disk, so any extension built that way gets its class.
- The result is what is served and cached; a cached copy is the class's own `Clone()`. The class's redact keys and
  the service's (`redact_keys`, the always-redacted ones) both hold: the deserializer reads the latter from the
  serialization and adds them to its own.
- Served as built, as before: a type not registered (its extension not loaded - a later lookup after the load
  gets the class, once the cached material is fetched again), or one whose deserializer cannot read a key-value
  serialization (it throws: a layout of its own).
- Material never touches disk: the buffer is in memory and zeroed after use.
- Not validated as `CREATE SECRET` would (BigQuery's "exactly one auth method"): as with a persistent secret read
  from disk; the service holds what an administrator created.
- BigQuery renews its own tokens from a service account key, an external account config or an authorized user, so
  those are what the service should hold for it (docs/concepts.md), not a bare `access_token`.

## Testing

- `test/extension/typed_secret_stub` (test-only, linked under `TRESOR_TEST_HTTPFS=1`, like acl_stub): types
  `typed_stub` (class `StubSecret`, deserializer `KeyValueSecret::Deserialize<StubSecret>`) and `opaque_stub` (a
  deserializer that throws); `typed_stub_project(name)` / `typed_stub_lookup(path)` cast as bigquery does,
  `opaque_stub_class(name)` names the class.
- `test/sql/attach/typed_secrets.test`: a `typed_stub` secret from the service is a `StubSecret` by name, by path
  and from the cache; its token stays redacted; an `opaque_stub` one is a `KeyValueSecret`. Without the change the
  first cast fails with `std::bad_cast` (checked).
- CI forbids skipping `require typed_secret_stub`.

## Implementation

- `src/tresor_storage.cpp`: `AsRegisteredType`, applied in `MaterialOf` before caching; the storage keeps its
  `DatabaseInstance`.
