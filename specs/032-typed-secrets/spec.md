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
  an extension): serialized as a key-value secret into memory, then read as `SecretManager::DeserializeSecret`
  reads a secret its type serialized itself (`CUSTOM`): the header (fields 100-103), then the type's own function.
  Any extension built that way gets its class; for a plain key-value type (httpfs's) it is the same secret.
- The result is what is served and cached; a cached copy is the class's own `Clone()`. The class's redact keys and
  the service's (`redact_keys`, the always-redacted ones) both hold: the deserializer reads the latter from the
  serialization and adds them to its own.
- Served as built: a type not registered (its extension not loaded) - and once it is, a cache hit is read back
  then, so the class does not wait for the material to expire; a type whose deserializer cannot read a key-value
  serialization (it throws: a layout of its own - silently, the extension's own error follows). An allocation
  failure or an internal error is not swallowed.
- Material never touches disk. The serialization's buffers are zeroed when freed - each growth's old one too (an
  allocator that wipes) - and the deserializer reads exactly the bytes written. Copies outside this step (the
  service's response body, the deserializer's temporaries) are as before.
- Not validated as `CREATE SECRET` would (BigQuery's "exactly one auth method"): as with a persistent secret read
  from disk; the service holds what an administrator created.
- BigQuery renews its own tokens from a service account key, an external account config or an authorized user, so
  those are what the service should hold for it (docs/concepts.md), not a bare `access_token`.
- The refresh provider (`CreateTresorProvided`) copies the material as a `KeyValueSecret`: right for the refreshable
  types, httpfs's, whose class that is.

## Testing

- `test/extension/typed_secret_stub` (test-only, linked under `TRESOR_TEST_HTTPFS=1`, like acl_stub): types
  `typed_stub` (class `StubSecret`, which redacts `token` and `project_key`; deserializer
  `KeyValueSecret::Deserialize<StubSecret>`) and `opaque_stub` (a deserializer that throws);
  `typed_stub_project(name)` / `typed_stub_lookup(path)` cast as bigquery does, `opaque_stub_class(name)` names the
  class.
- `test/sql/attach/typed_secrets.test`, with a secret written through tresor and one the fake seeds (`typed_seed`):
  of the class by name and by path, and from the cache (one fetch, counted by the fake); HUGEINT, STRUCT and LIST
  values intact; the class's own redaction of a key the service does not redact; an `opaque_stub` secret is a
  `KeyValueSecret`. Without the change the first cast fails with `std::bad_cast` (checked).
- Not covered by a test (the stub is linked, its types registered from the start): a cache hit read back after the
  type's extension loads; reviewed.
- CI forbids skipping `require typed_secret_stub`.

## Implementation

- `src/tresor_storage.cpp`: `DeserializerOf` and `AsType` (with a wiping allocator), applied in `MaterialOf`
  before caching and on a cache hit fetched while its type was not registered (`Material::typed`); the storage
  keeps its `DatabaseInstance`.
