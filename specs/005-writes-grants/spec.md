# Spec 005: writes — `CREATE / DROP PERSISTENT SECRET … IN corp`, annotations, grants

- **Status**: implemented; writes and grants are an administrator's, grants to roles and groups with `use` only - [009](../009-permissions-v2/spec.md)
- **Date**: 2026-09-23
- **Author**: VGSML (with Claude)

## Summary

The attached service becomes writable with DuckDB's own statements:
- `CREATE PERSISTENT SECRET … IN corp` stores a secret in the service;
- `IF NOT EXISTS` and `OR REPLACE` map to HTTP preconditions;
- `DROP PERSISTENT SECRET … FROM corp` deletes it;
- `SET default_secret_storage = 'corp'` makes the service the default for persistent secrets.

Annotations and grants are table functions of the catalog: `corp.annotate_secret`, `corp.grants`,
`corp.grant_secret` and `corp.revoke_secret`. Whether each call is allowed is the service's
decision; the client maps its answers to clear errors.

## Problem

After spec 004, secrets can only be read. Putting a credential into the service, or sharing it with
a role, still needs another tool. The protocol has had writes and grants since its first draft
(*Conditional writes*, *Grants*).

## Design

### Writes through DuckDB's secret manager

`TresorSecretStorage::StoreSecret(secret, on_conflict)` sends
`PUT /v1/secrets/{name}` with `{type, provider, scope, params, redact_keys}`:

| SQL | `on_conflict` | Request | On 412 |
| --- | --- | --- | --- |
| `CREATE PERSISTENT SECRET x IN corp (…)` | ERROR | `If-None-Match: *` | error: already exists in `corp` |
| `… IF NOT EXISTS …` | IGNORE | `If-None-Match: *` | nothing (duckdb's own `IGNORE` contract: no entry) |
| `CREATE OR REPLACE …` | REPLACE | no precondition | — |

- **Name.** DuckDB compares secret names case-insensitively, while the service compares them exactly.
  - A secret the service already lists is addressed by the service's own spelling, found
    case-insensitively in the list. That covers `DROP`, `OR REPLACE`, management calls and name
    lookups, so a secret another tool named `CRM_ro` is reachable.
  - A new secret is stored in lower case, the canonical form the protocol page asks for.
- **Params.** Every non-NULL entry of the `KeyValueSecret` map becomes a param; a NULL is omitted,
  since the protocol has no NULL param and the reference server refuses one. A `VARCHAR` is a bare
  string.
  Anything else is `{type, value}`: the type is `LogicalType::ToString()`, and the value is its JSON
  form (numbers as their exact text, `LIST`/`ARRAY` as arrays, `STRUCT`/`MAP` as objects). This is
  the inverse of spec 004's reading, so a secret round-trips without loss.
  - `redact_keys` are the secret's own, but only those that are params. A DuckDB secret type may
    list redact keys a given secret does not carry (a tresor token secret has no `client_secret`),
    and the reference server rightly refuses those with 422. The conformance run found this.
  - A secret that is not a `KeyValueSecret` is refused: the protocol has no other shape.
- **Answers.** `403 no_verb` becomes "you may not create/replace x in corp" and `422` shows the
  service's detail. The service's own errors are shown as spec 002 does (type + detail).
- **Drop.** `DropSecretByName(name, on_entry_not_found)` sends `DELETE /v1/secrets/{name}`. A `404`
  is an error, or nothing for `IF EXISTS`. A `403` is "you may not delete".
- **After a write**, the storage's list is marked stale and the name's cached material dropped. A
  generation counter keeps a refresh that started before the write from storing its older list,
  so the next lookup sees the change.
- **What duckdb enforces before the storage is called:**
  - the secret's type must be registered (an `s3` secret needs httpfs loaded, as for any storage);
  - `allow_persistent_secrets = false` refuses every persistent write, the service's included;
  - `CREATE TEMPORARY SECRET … IN corp` is refused, because the storage is persistent.
- **Writes are not transactional.** The service has no transaction to join: a `CREATE … IN corp`
  takes effect when it runs, and a `ROLLBACK` does not undo it. This is the same for every remote
  storage.
- **`DROP SECRET x` without `FROM`** finds a secret by name across storages (duckdb's rule), and by
  name tresor finds only secrets the caller may `use` (spec 004). `DROP … FROM corp` needs only
  `delete`.

### Management functions (table functions of the catalog)

| Call | Request | Returns |
| --- | --- | --- |
| `corp.annotate_secret(name, comment)` | `PATCH /v1/secrets/{name}` `{comment}` | the descriptor's name, comment and version |
| `corp.grants(name)` | `GET …/grants` | `id, principal, verbs[]`, one row per grant |
| `corp.grant_secret(name, principal, verbs)` | `PUT …/grants/{id}` | the grant as stored |
| `corp.revoke_secret(name, principal)` | `DELETE …/grants/{id}` | the revoked grant |

- **Grant ids.** A grant id belongs to the client.
  - `grant_secret` reads the grants first. If the principal already has one, it is replaced under
    its id, and any other grants to that principal (another tool may have made several) are
    removed, so the principal ends up holding exactly the verbs given.
  - A new grant's id is `g-` plus the FNV-1a 64 hash of the principal, in hex. It is self-contained,
    so no DuckDB version or build flag changes it, and every client computes the same id.
  - `revoke_secret` removes every grant to the principal. A principal with no grant is an error.
  - Both invalidate the storage's cache, since the caller's own verbs may change.
- **`grants()`** emits its rows a chunk at a time.
- **When calls run.** Each call runs when its table function is scanned (`CALL corp.… (…)` or
  `FROM corp.… (…)`), once per statement. Arguments must be constants.
- **Answers.** The same mapping as for writes. A secret the caller cannot see is "no secret x in
  corp".

### Protocol

No change to requests or responses. The protocol page states two client-side rules:
- writes are immediate, not transactional;
- a grant id is the client's choice (already implied by `PUT …/grants/{id}`).

## Enforcement & security

- The service decides every verb; the client adds no authority and caches no permission.
- A write never logs params, and tresor's own errors never quote one. A service's `detail` is shown
  bounded to 200 characters. Keeping values out of it is the service's responsibility, and the
  reference server's details carry none.
- **What a stored secret holds.** A secret created with a resolving provider (for example s3's
  `credential_chain`) stores the writer's resolved, possibly temporary, credentials in the service,
  where grantees receive them. The docs say so.
- The secret's material is sent once, over the session's HTTPS, and is not cached by the write.

## Testing

- **The fake** grows in-memory writes:
  - `PUT` honouring `If-None-Match: *`, `DELETE`, `PATCH` and grants;
  - a name the caller may not create (`forbidden_*`) answers 403;
  - material written is readable back.
- **`test/sql/attach/writes.test`:**
  - `CREATE PERSISTENT SECRET … IN corp` of type `tresor` (the only secret type the test shell
    registers without an extension);
  - the created secret listed with its version, the second `CREATE` failing, and `IF NOT EXISTS`
    silent;
  - `OR REPLACE` changing it (scope and version);
  - `default_secret_storage = 'corp'`;
  - `DROP … FROM corp`, `IF EXISTS`, and a missing secret;
  - 403 on a forbidden name, and a temporary secret refused;
  - annotate, grants list/grant/replace/revoke, and a revoke without a grant;
  - a write inside a transaction that is rolled back still being applied (documented behaviour).
- **The fake refuses redact keys that are not params**, as the reference server does.
- **Typed writes with the core `http` type**, which the test shell has: a `MAP` param and a
  redacted key are written, found by `which_secret`, and read back typed. A local `http` secret wins
  a tie against the service. `DROP SECRET MyHttp` without `FROM` works by the user's spelling. A
  seeded `Mixed_Case` secret is reached by any spelling and addressed as the service spells it.
  NULL verbs are refused.
- The fake refuses NULL params and redact keys that are not params, as the reference server does.
- **The conformance suite** (`writes.test`), against the reference server as the `etl` service:
  - create, list, conflict, replace, annotate;
  - grant to a role, list, revoke, drop.

## The review's findings (applied)

- **Names by case.** Mixed-case names were lowercased on write but compared exactly on read
  (`DROP SECRET MyLake` failed), and a service's mixed-case names were unreachable. Now names are
  resolved against the list case-insensitively and sent in the service's spelling.
- **NULL.** `grant_secret(…, NULL)` raised an internal error, and a NULL param was sent in a form
  the reference server refuses. Now the verbs are checked and NULL params omitted.
- **Grants.** `grant_secret` left the other grants to a principal in place. It now removes them.
- **Grant ids.** They used DuckDB's internal hash, which changes between versions and is 0 in some
  builds. They now use FNV-1a.
- **The test shell has a typed type (`http`)**, so typed writes, lookup after a write, the
  local-wins-tie case (deferred by spec 004) and case handling are all tested now.
- **Smaller fixes:** `grants()` is chunked; a write stops an in-flight refresh from landing; grants
  invalidate the cache; a service's `detail` is bounded; the 403 on delete carries the service's
  words; `JsonString` is shared; spec 004 was left as merged.

## Alternatives considered

- **Buffering writes until COMMIT.** The secret manager calls the storage at statement time. A
  buffered write would report success for a CREATE the service may still refuse at commit, and
  would still not be atomic across services.
- **`CALL corp.create_secret(…)` instead of CREATE SECRET.** It duplicates DuckDB's syntax, providers
  and validation. The secret manager already routes `IN corp` to the storage.
- **Random grant ids.** Two clients granting the same principal would create two grants.

## Follow-ups

- spec 006: dynamic secrets and the `REFRESH auto` provider for httpfs.
- spec 007: delegation rules (`add_delegation`, …) with the server side in the reference server.
