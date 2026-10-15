# Spec 033: the right secret reaches the extension - httpfs, postgres_scanner, iceberg

- **Status**: implemented
- **Date**: 2026-10-15
- **Author**: hugr lab
- **Asked by**: tresor-server's review of the extensions' sources (bigquery's `bad_cast`, spec 032; name-only lookups;
  iceberg's `expires_in`); the owner approved a first version with three consumers, as a CI job of its own

## Summary

Until now the tests stopped at DuckDB's lookup: `which_secret` names the service's secret, `tresor_secret_param`
shows its values. Nothing proved that the extension which consumes a secret gets it and uses it - that a
request is signed with the served key, that a database login is the served user. This spec adds those tests for
three consumers - httpfs (s3, http), postgres_scanner and iceberg - built at the commits DuckDB's own 2.0 tree pins,
against the fake service, a fake S3 / HTTP endpoint / Iceberg REST catalog in the same fake, and a real Postgres.

## Problem

- A consumer can find a secret and still not use it: a lookup by name only (postgres_scanner), a cast to a class of
  its own (bigquery, fixed in 032), a type it reads only in one shape (iceberg's `expires_in`), options normalized
  only by its own `CREATE SECRET` (postgres_scanner's aliases), a token it expects to have been fetched at `CREATE
  SECRET` (iceberg). None of this shows in `which_secret`.
- The owner's decision for database consumers (2026-10-15): a secret read at ATTACH belongs to whoever attaches - on
  an acl node, the instance itself; per-user values only for per-request consumers (HTTP, object storage). The
  tests should show what the consumers actually do.

## Design

### Build

- `TRESOR_TEST_CONSUMERS=1` (opt-in, `extension_config.cmake`) builds postgres_scanner, avro and iceberg at the
  commits - and with the patches (`APPLY_PATCHES`, duckdb's `.github/patches/extensions/`) - that duckdb's 2.0 tree pins in `duckdb/.github/config/extensions/{postgres_scanner,avro,iceberg}.cmake`: postgres
  `9671d2c`, avro `758fb60`, iceberg `5b9ff89`. Move them with the duckdb pin, as httpfs. iceberg loads avro (and
  parquet) at its own load, and talks HTTP through httpfs, so the flag goes with `TRESOR_TEST_HTTPFS=1`.
- iceberg and avro are statically linked into the test build (`require iceberg`). postgres_scanner is **not**: its
  CMakeLists links libpq (`PostgreSQL::PostgreSQL`) into the loadable extension only, so a static link of it fails
  (`libduckdb` misses every `PQ*` symbol; duckdb's own CI never links it either). `postgres.test` loads it by build
  path, as tresor itself is loaded (`require-env TRESOR_TEST_CONSUMERS`).
- Their vcpkg dependencies (libpq; aws-sdk-cpp, curl, roaring, jansson, liblzma, snappy, zlib, avro-c) reach the build
  through the **merged manifest** extension-ci-tools already writes (`USE_MERGED_VCPKG_MANIFEST`): each loaded
  extension's own `vcpkg.json` and overlay ports are merged in at the configure step. tresor's `vcpkg.json` is
  unchanged, and without the flag the merged manifest is what it was - the distribution build (which never sets
  the flag) and the other CI jobs build none of it. No vcpkg feature or second manifest was needed.
- tresor itself is unchanged: no consumer needed a fix in tresor for what is tested here.

### The fake (`test/fake/fake_service.py`)

- A realm `consumers` (`ATTACH 'tresor:127.0.0.1:<port>/consumers'`) with secrets of its own (`consumer_secrets`),
  so the other realms' listings - which the attach tests count - are untouched. Their endpoints are the fake's own:
  - `/cbucket/…`, a path-style S3: rebuilds the SigV4 canonical request from what arrived and checks the signature
    with the secret of the key named in `Credential=`; answers CSV `key_id,signature` or `403`.
  - `/chttp/…`, `/chttp-dyn/…`: answer CSV `auth,tenant` - the `Authorization` and `X-Tenant` headers that arrived.
  - `/cice/…`, an Iceberg REST catalog: `GET /v1/config`, `POST /v1/oauth/tokens` (client_credentials, Basic auth of
    the catalog's client; tokens `ICE-RENEWED-<n>`), `GET /v1/namespaces` - one namespace named after the bearer
    token (`seen_<token>`); any token not issued for the tests is `401`.
  - `GET /_consumers`: what those endpoints saw (the S3 key and signature check, the tokens the catalog received, the
    token requests).
- The fake's request accounting (`leaked`, spec 020) ignores the consumers' paths: those requests are the
  extensions', not tresor's.

### Tests (`test/sql/consumers/`, run by `scripts/ci/test_attach.sh "" 'test/sql/consumers/*'`)

- `httpfs.test`: an S3 read (`read_csv('s3://cbucket/who.csv')`) answered only for a valid signature by the served
  key and secret - with the served `endpoint`, `url_style`, `use_ssl`, `region`; an http secret's `bearer_token` and
  `extra_http_headers` on httpfs's request; a dynamic http secret's generated token (spec 029); one material fetch per
  secret; nothing after `DETACH`.
- `postgres.test` (`require-env TRESOR_TEST_PG_PORT`): `ATTACH … (TYPE postgres, SECRET c_pg)` logs in as the served
  user (`current_user`); the unnamed default (`__default_postgres`, served by the service); a served wrong password
  is refused by the server; a served alias (`username`) is not libpq's name; the login stays with the attached
  database after the service is detached.
- `iceberg.test`: an ATTACH with no options takes the uri and token of the service's unscoped iceberg secret; a named,
  dynamic secret's generated token; `expires_in` as an INTEGER is honoured (iceberg renews the token itself, with the
  served client credentials), as a string it is ignored; a secret without a token is refused.

## Findings - how each consumer finds and uses a secret (at the pinned commits)

### httpfs (`abdd053`)

- By **path** only: `KeyValueSecretReader` (`LookupSecret(path, type)`) per request - `s3`/`r2`/`gcs`/`aws` for
  `s3://…` (and `http`, merged in unless `merge_http_secret_into_s3_request = false`), `http` (and `bearer`) for
  `http(s)://…`. Every request looks up again: a per-user value (a dynamic secret, a session's own) is the caller's
  on each request - this is the consumer the owner's decision means by per-request.
- Reads plain `KeyValueSecret` values (`TryGetValue`), `extra_http_headers` as a `MAP(VARCHAR, VARCHAR)` - typed values
  from the service arrive as their types (spec 004); a dynamic s3 secret refreshes through the `tresor` provider
  (spec 006, `refresh.test`).

### postgres_scanner (`9671d2c`)

- By **name** only: `SECRET <name>` is `GetSecretByName(name)` over every storage, then `local_file`; no SECRET is the
  name `__default_postgres` - a service secret of that name is the default. Scope is never consulted.
- Read **once, at ATTACH**: the options become a connection string kept by the attached catalog and its pool. The
  login is whoever attached it - per the owner's decision, on an acl node the instance itself; a per-user (dynamic)
  postgres secret is fixed at its first ATTACH, never re-read per statement. `DETACH` of the service leaves the
  attached database logged in.
- Only libpq's own option names are read (`host`, `port`, `dbname`, `user`, `password`, …). `CREATE SECRET`
  normalizes the aliases `database`, `username`, `hostname`; a served secret is not created there, so a service
  must store the canonical names. A secret written through tresor (`CREATE PERSISTENT SECRET … IN corp`) is
  normalized before it is sent, so this concerns secrets written into the service by other means.
- `rds` secrets (`aws_rds_secret`) are looked up by name too (not tested).

### iceberg (`5b9ff89`)

- The catalog secret (`iceberg`): by **name** (`SECRET <name>`), else `LookupSecret("", "iceberg")` - an empty path,
  which only a secret **without a scope** matches (score 0). A service's iceberg secret meant as the default must
  therefore have no scope; a scoped one is reachable by name only.
- A stored secret is used **as it is**: it must hold `token`. iceberg's own `CREATE SECRET` with client credentials
  logs in at creation and stores the token; a served secret is never logged in - without a token the ATTACH fails
  ("Failed to retrieve OAuth2 token"). So the service holds a token - generated for the caller (spec 029) where it
  must be fresh, or kept fresh by the service.
- `expires_in` is read **only as an INTEGER** (`expires_in.type().id() == INTEGER`, and > 0 for a stored secret). A
  generated value is always a string (spec 029), so a generated `expires_in` is ignored: the token then never
  expires for iceberg. When the service stores `expires_in` as a typed INTEGER together with `client_id`,
  `client_secret` and `oauth2_server_uri`, iceberg renews the token itself past it (and on a `401`), with those
  credentials - the catalog's OAuth client then sits in the served secret.
- Read **once, at ATTACH**: the token and credentials live in the attached catalog's authorization; like a postgres
  login, it belongs to whoever attached.
- Storage credentials: `GetStorageSecret` is by name, `__default_s3`/`__default_aws`, then `LookupSecret("s3://",
  type)` (GLUE / S3 Tables only); the catalog's `http` secret is `LookupSecret(<catalog url>, "http")` (proxy
  settings). Not tested here (no table scans: the fake catalog serves no tables).
- `GetHTTPSecret` and `FromAttachOptions` `dynamic_cast` the secret to `KeyValueSecret` - what tresor serves for
  iceberg's type (its deserializer is `KeyValueSecret`'s).

## Enforcement & security

- Test-only: the consumers are built only under `TRESOR_TEST_CONSUMERS=1`; never linked into tresor, never in a
  distribution build.
- The values in the fake and the tests are test values (keys, tokens, the Postgres login of a throwaway container);
  no real credential appears. The tests run with `TRESOR_KEYCHAIN=memory` (test_attach.sh).

## Testing

- CI job `consumers-linux` (`.github/workflows/ci.yml`, Linux only): builds with `TRESOR_TEST_HTTPFS=1
  TRESOR_TEST_CONSUMERS=1`, a Postgres service container (`postgres:17-alpine`, the login `PG_LOGIN` the fake
  serves) on `TRESOR_TEST_PG_PORT`, runs the consumer suites and forbids their skips (`scripts/ci/assert_ran.sh`).
- Locally: `TRESOR_TEST_HTTPFS=1 TRESOR_TEST_CONSUMERS=1 GEN=ninja make`, a Postgres
  (`docker run -d -e POSTGRES_USER=tresor_pg -e POSTGRES_PASSWORD=pg-s3cret -p 127.0.0.1:55433:5432
  postgres:17-alpine`), then `TRESOR_TEST_CONSUMERS=1 TRESOR_TEST_PG_PORT=55433 scripts/ci/test_attach.sh ""
  'test/sql/consumers/*'`. On macOS (arm64): 3 test cases, 58 assertions, all passed; the attach suites (both HTTP
  clients) and the unit suites pass on the same build with the extended fake.
- Checked to discriminate: with the served S3 secret's value changed, the fake S3 refuses the signature (403) and
  `httpfs.test` fails.

## Alternatives considered

- Adding the consumers' dependencies to tresor's `vcpkg.json` (or a vcpkg feature): unnecessary - the merged manifest
  already carries each loaded extension's own - and it would have touched the distribution build's manifest.
- The consumer secrets in the fake's ordinary realm: the attach tests count and list that realm's secrets.
- A real MinIO / Iceberg REST server (docker): heavier, and they would not say which key or token they received; the
  fake answers with what reached it.

## Follow-ups

- More consumers (bigquery, mssql, azure, gcs's bearer token, ducklake's metadata secret), and iceberg's storage
  credentials with a table scan.
- iceberg: an `expires_in` a service generates is a string; whether the protocol should let a generated value carry
  a type, or iceberg accept a string, is open (tresor-server).
