# Spec 018: variables - named strings a service holds, an optional part of the protocol

- **Status**: implemented
- **Date**: 2026-10-01
- **Author**: hugr lab
- **Asked by**: the owner, with tresor-server (the `tresor_value` idea of spec 016's follow-ups)

## Summary

A service may hold **variables** besides secrets: named strings its callers read by name. Examples are a
bucket, an endpoint, a dataset's path, or a setting a team shares.
- A variable's value may reference a vault. The service resolves the reference on read, and such a value
  is marked `sensitive`.
- Variables are **optional** in `duckdb-secrets/1`. A service advertises them in its discovery
  (`capabilities.variables`), and one without them stays a complete service.

```sql
SELECT corp.variable('lake_bucket');                                   -- s3://corp-lake
SELECT corp.variable('region', fallback := 'eu-west-1');               -- no such variable: the fallback
SET VARIABLE bucket = corp.variable('lake_bucket');                    -- into DuckDB's own variables
FROM corp.variables();                                                 -- name, comment, sensitive, version, permissions
CALL corp.set_variable('lake_bucket', 's3://corp-lake');               -- an administrator
CALL corp.set_variable('db_password', 'ref+azkv://corp-vault/db-pass');   -- a reference (tresor-server)
CALL corp.annotate_variable('lake_bucket', 'The sales team''s lake');
CALL corp.grant_variable('lake_bucket', 'role:analysts', ['use']);
FROM corp.variable_grants('lake_bucket');
CALL corp.revoke_variable('lake_bucket', 'role:analysts');
CALL corp.drop_variable('lake_bucket');
```

## Problem

Teams share more than credentials. They share where the data is, which endpoint to use and which
dataset is current. Today these values are copied into scripts and notebooks, and they drift. Some of
them are half secret, such as a connection string with a password in it.

tresor already has the place for such values: one login, roles, grants, an audit and a service the
organisation runs. It lacks only a value that is not a DuckDB secret.

## Design

### The protocol (`website/docs/protocol.md`, a section *Variables*)

- **Optional.** The capability is `capabilities.variables`; absent means `false`. A client looks only at
  the capability and never probes a route.
- **Routes.** `/v1/variables` (a list without values) and `/v1/variables/{name}` (`GET` with the value,
  `PUT {value, comment?}`, `DELETE`, `PATCH {comment}`), plus `/{name}/grants[/{id}]`.
  - They behave as the secret routes: conditional writes (`If-None-Match: *`, `If-Match`, ETags), the
    errors, and the name rules of spec 016.
- **The value** is a UTF-8 string, and 64 KiB is always accepted.
  - **References** (a vault, a key store) use the service's own syntax. The service resolves them on
    read, and only an administrator writes one.
  - A reference that does not resolve answers `503`, or `500 service_error` when it never will.
- **`sensitive`** is `true` when the value is or holds material the service keeps as a secret. A client
  then treats the value as material:
  - no log, audit or error ever shows it;
  - it is cached no longer than a secret's material;
  - it is never served across callers.
- **Permissions** are the secrets' own. Administrators create (`permissions.create`) and manage, roles
  get `use` through grants, and delegation works the same.

### tresor

- **The capability.** It is read at ATTACH from the discovery, as `delegation` is.
  - Without it, every variable function fails with: `<catalog>'s service does not hold variables
    (capabilities.variables)`.
  - The functions are registered in every tresor catalog either way, so a script names them the same
    way against any service.
- **`corp.variable(name [, fallback])`** is a **scalar** function of the catalog that returns
  `VARCHAR`.
  - A missing variable is an error, and so is one the caller cannot see (the protocol answers both `404`).
    With a `fallback`, a `404` gives the fallback. A `403` (seen without `use`: an administrator) and a
    failure (a reference that does not resolve) stay errors.
  - A NULL name gives NULL.
  - **A name is a string, sent as given**, not a DuckDB identifier: no lower case. Only a new one
    (`set_variable`) is checked against the names a service may refuse (spec 016). An existing one is
    the service's to judge, and it can be read, dropped and granted whatever its shape.
  - `fallback` is passed by position or as `fallback := …`. It is not called `default`, because
    `default := …` is a syntax error in DuckDB (a reserved word).
  - It is a scalar so that a value goes where an expression goes: `SET VARIABLE`, a `WHERE`, a
    `read_parquet(corp.variable('lake') || '/*.parquet')`.
  - It is **volatile**: never folded into a plan, where `EXPLAIN` and the profiler would show a value,
    sensitive ones included. A prepared statement reads anew.
  - Each name is asked once per chunk, a missing one included: a per-row fallback does not send a
    request per row. Then the caller's cache answers.
- **Caching.** A value is cached per caller, as secret material is:
  - the node, and each acl session through its grant, have their own cache;
  - a non-sensitive value is reused for as long as a list is trusted (30 s);
  - a sensitive value is reused no longer than static material (5 min);
  - a write through tresor (set, drop, a grant) drops the name's cached values at once;
  - DETACH and an acl session's end drop them too.
- **`corp.variables()`** is a table function: `name, comment, sensitive, version, permissions`, with no
  value.
- **Management** (administrators):
  - `set_variable(name, value [, comment := …])` is `PUT` without a precondition. It creates or
    replaces; `if_not_exists := true` sends `If-None-Match: *`.
  - `annotate_variable`, `drop_variable` (with `if_exists := true`), `grant_variable`,
    `revoke_variable` and `variable_grants` mirror the secrets' functions (specs/005).
  - A new name the protocol lets a service refuse is never sent (spec 016).
- **Audit.** It uses TRSA's existing kinds with `secret_type = 'variable'`: `lookup` for a read,
  `write`, `drop`, `annotate`, `grant` and `revoke`. There is no new kind, and the contract layout is
  unchanged. A value never appears in an event.
- **Under an acl session.** Reads and writes go through the session's grant, as the secrets' calls do.
  `act_for_sessions` is unchanged.

### The reference server

- It advertises `variables: true` and keeps variables in its store beside secrets: the same encrypted
  file, the same grants and policy.
- It resolves no references (it has no vault), so `sensitive` is always `false` there.
- The namespace comes from the route a request matched, never from its path: a secret's name may hold
  `/v1/variables`.
- A store written by this version keeps its variables in a field an older reference server does not
  know. Such a server would drop them at its next write.
- `PUT` checks the name (spec 016) and the value: UTF-8, up to 64 KiB.

## Enforcement & security

- **A value is data, never code.** tresor returns it as a string, and what a query does with it is the
  query's business.
- **A sensitive value is material.** It never appears in a log, an audit or an error, it is cached per
  caller only, and it is gone at DETACH.
- **References are the service's.** A client cannot make the service read a store, because only an
  administrator writes a reference, within the service's allowlist.
- **A service without the capability** is never sent a variable request.

## Testing

- `test/sql/attach/variables.test` (the fake service, which advertises the capability):
  - read; the fallback on a `404` (by position, by name, NULL); an error on a `403`;
  - a resolved reference, marked sensitive;
  - the list;
  - the cache: a second read asks nothing;
  - set, replace and `if_not_exists`;
  - annotate, grant, revoke and drop (with `if_exists`);
  - no value in the audit log;
  - per caller under an acl session (acl_stub): the node and the session's user read different values;
  - a realm without the capability: the clear error from every function, and no request sent (the
    fake counts them).
- `test/sql/conformance/variables.test` runs against the reference server and Keycloak
  (`require-env TRESOR_CONFORMANCE_VARIABLES`, which `test_keycloak.sh` sets for the reference server).
  A service without variables does not run it.
- The reference server's Go tests cover the routes, preconditions, grants, names and value size, and the
  store keeps variables apart from secrets in its encrypted file.

## Alternatives considered

- **Variables as a secret type** (`TYPE variable`). They would take part in secret lookups by scope,
  which means nothing for a value read by name, and `duckdb_secrets()` would list strings as secrets.
- **A table function `corp.variable(name)`.** It cannot stand where an expression stands
  (`SET VARIABLE`, `||`).
- **Mandatory in the protocol.** Every service would need storage and grants for something many will
  not use.

## Follow-ups

- tresor-server: variables in its stores, and `ref+azkv://` resolution with `sensitive`.
- **Typed values** (an `INTEGER`, a `LIST`), if strings prove too narrow. That is a protocol change.
