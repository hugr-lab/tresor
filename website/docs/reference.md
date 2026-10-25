---
sidebar_position: 3.9
title: SQL reference
---

# SQL reference

Everything tresor adds to DuckDB, in one place. `corp` stands for the name of an attached service.

## ATTACH

```sql
ATTACH 'tresor:<host>[:port][/base]' AS corp [(option value, …)];
```

The path has no scheme: https is implied. With `https://` DuckDB would require httpfs and attach read-only
before tresor sees the path.

| Option | Value | Default | Meaning |
| --- | --- | --- | --- |
| `LOGIN` | `'auto'`, `'browser'`, `'device'` | `'auto'` | A person's login. `auto` opens a browser where one can open, else the device flow ([Getting started](./getting-started.md)). Naming it means a person logs in: no `tresor` secret is looked up. |
| `ISSUER` | the issuer URL | — | Which identity provider, when the service's discovery lists several. Required then. |
| `SECRET` | a `tresor` secret's name | the one whose `SCOPE` covers the path | A service's login (below). Not with `LOGIN`. |
| `INSECURE_HTTP` | boolean | `false` | Plain http, for a service on this machine only (`127.0.0.1`, `::1`, `localhost`). |
| `LOGIN_TIMEOUT` | seconds | `300` | How long a person's login waits. |
| `REMEMBER` | boolean | `true` | Keep a person's login in the credential store (`tresor_keychain`). `REMEMBER true` is refused for a service's login. |
| `ACT_FOR_SESSIONS` | boolean | `false` | On a duckdb-acl node: act for each session's user ([Concepts](./concepts.md#on-a-duckdb-acl-node)). Needs a service login of flow `client_credentials` or `federated`. |
| `EXCHANGE` | `'token_exchange'`, `'on_behalf_of'` | `'token_exchange'` | With `ACT_FOR_SESSIONS`: RFC 8693, or Entra's On-Behalf-Of. |
| `EXCHANGE_SCOPE` | text | — | With `ACT_FOR_SESSIONS`: the scope asked for. Required with `on_behalf_of` (`api://…/.default`). |
| `EXCHANGE_AUDIENCE` | text | the discovery's `audience`, when the node's own token is issued for it | With `ACT_FOR_SESSIONS`: the audience users' tokens are exchanged for. Required when the discovery sets `audience_parameter`; ignored with `on_behalf_of` (its scope decides). |
| `SESSION_GRANT_WAIT` | seconds, 0 to 600 | `10` | With `ACT_FOR_SESSIONS`: how long a statement waits for its session's delegation grant. |

## The `tresor` secret: a service's login

```sql
CREATE SECRET <name> (TYPE tresor, SCOPE 'tresor:<host>', FLOW '<flow>', …);
```

An `ATTACH` with no `LOGIN` takes the `tresor` secret whose `SCOPE` covers its path, or the one `SECRET`
names. Only `FLOW` and the options of that flow are accepted:

| `FLOW` | Required | One of | Optional |
| --- | --- | --- | --- |
| `client_credentials` | `CLIENT_ID`, `ISSUER` | `CLIENT_SECRET`, `PRIVATE_KEY_FILE` | `OAUTH_SCOPE`, `KEY_ID`, `CERTIFICATE_FILE` (both with `PRIVATE_KEY_FILE`) |
| `federated` | `CLIENT_ID`, `ISSUER` | `ASSERTION_FILE`, `ASSERTION_SOURCE` (`'github_actions'` with `ASSERTION_AUDIENCE`, `'azure_managed_identity'`) | `OAUTH_SCOPE`, `ASSERTION_AUDIENCE` (with `ASSERTION_SOURCE`), `IDENTITY_CLIENT_ID` (with `azure_managed_identity`) |
| `managed_identity` | `ISSUER`, `AUDIENCE` | — | `CLIENT_ID` (a user-assigned identity) |
| `token` | `TOKEN` | — | — |

`CLIENT_SECRET` and `TOKEN` are redacted. A file option names a path that is read at each login, never
stored. Recipes for each platform: [Pipelines](./pipelines.md).

The `tresor` provider of the `s3`, `r2`, `gcs` and `aws` types (`TRESOR_SERVICE`, `TRESOR_SECRET`) is how
httpfs's `REFRESH auto` renews a dynamic secret from the service. httpfs calls it; you do not.

## Settings

| Setting | Values | Default | Meaning |
| --- | --- | --- | --- |
| `tresor_keychain` | `auto`, `off`, `memory` | `auto` (from `TRESOR_KEYCHAIN` when set; `memory` in wasm) | Where a person's login is remembered: the OS credential store, nowhere, or this instance's memory. |
| `tresor_http_client` | `builtin`, `duckdb` | `builtin` (from `TRESOR_HTTP_CLIENT` when set; `duckdb` in wasm) | tresor's HTTP client: its own, or DuckDB's (httpfs natively, the browser's in wasm). An ATTACH keeps the one it started with. |
| `tresor_audit_level` | `off`, `denied`, `all` | `off` | What tresor writes to DuckDB's log, type `tresor` (below). |

DuckDB's own `ca_cert_file` is trusted by tresor too, and `enable_external_access = false` stops tresor's
requests unless `allowed_directories` / `allowed_paths` name their URL ([Security model](./security.md)).

## Functions

### Of the extension

| Function | Returns | |
| --- | --- | --- |
| `tresor_version()` | `VARCHAR` | tresor's version (`v0.1.0`). |
| `tresor_login(service [, login := …, issuer := …, insecure_http := …, remember := …, prompt := …])` | `service`, `issuer`, `client_id`, `flow`, `status`, `url`, `user_code`, `expires_at` | A person's login, answered at once and completed in the background ([From DuckDB UI, Python and IDEs](./clients.md)). `prompt` is `login`, `select_account`, `consent` or `none`. |
| `tresor_logoff([catalog] [, service := …, issuer := …, client_id := …, detach := …])` | `service`, `issuer`, `client_id`, `removed`, `revoked`, `detached` | Forget a login: every login attached here, the one of a catalog, or one named by service, issuer and client id (all three). Also forgets an application's tokens (`tresor_web_token`). `detach := false` keeps the catalogs, waiting for the next login. |
| `tresor_web_login(service, refresh_token [, issuer := …, insecure_http := …])` | `service`, `issuer`, `client_id` | A login made elsewhere (a web page), handed over by its refresh token, in memory only ([In a web application](./web.md)). |
| `tresor_web_token(service, access_token [, issuer := …, insecure_http := …])` | `service`, `issuer`, `expires_at` | The application's own access token for the service, and each renewed one ([In your application](./embedding.md)). |
| `tresor_secret_param(secret, key)` | `VARCHAR` | One parameter of a secret as DuckDB holds it, with its type (`INTEGER 1433`). A redacted key shows `<TYPE> <redacted>`. Needs `allow_unredacted_secrets`. A diagnostic. |

`service` is `'tresor:<host>'`, as in `ATTACH`. Pass tokens as prepared-statement parameters, never in the
statement's text.

### Of an attached service

| Function | Returns | |
| --- | --- | --- |
| `corp.whoami()` | `service`, `issuer`, `subject`, `roles`, `actor`, `expires_at`, `can_create`, `login`, `name` | Who is logged in. `login` is `browser`, `device`, `remembered`, `page`, `client_credentials`, `private_key_jwt`, `federated`, `managed_identity` or `token`. |
| `corp.secrets()` | `name`, `type`, `provider`, `scope`, `comment`, `owner`, `permissions`, `dynamic`, `updated_at`, `version` | The secrets the caller may see, never their material. |
| `corp.grants(secret)` | `id`, `principal`, `verbs` | A secret's grants (administrators). |
| `corp.grant_secret(secret, principal, ['use'])` | `id`, `principal`, `verbs` | Give `use` to a `role:` or `group:` principal. |
| `corp.revoke_secret(secret, principal)` | `id`, `principal`, `verbs` | Take it away. |
| `corp.annotate_secret(secret, comment)` | `name`, `comment`, `version` | Set the comment. |
| `corp.variable(name [, fallback])` | `VARCHAR` | A variable's value (scalar). With a fallback, a missing one is the fallback; one you see without `use` stays an error. |
| `corp.variables()` | `name`, `comment`, `sensitive`, `version`, `permissions` | The variables the caller may see. |
| `corp.set_variable(name, value [, comment := …, if_not_exists := …])` | `name`, `version` | Create or replace a variable (administrators). |
| `corp.drop_variable(name [, if_exists := …])` | `name`, `dropped` | Delete it. |
| `corp.variable_grants(name)`, `corp.grant_variable(name, principal, ['use'])`, `corp.revoke_variable(name, principal)`, `corp.annotate_variable(name, comment)` | as for secrets | The same for variables. |
| `corp.act_for_sessions([exchange := …, exchange_scope := …, exchange_audience := …, session_grant_wait := …])` | `service`, `exchange`, `audience`, `scope`, `changed` | Start acting for duckdb-acl's sessions later than ATTACH, with the same checks. |

The variable functions are refused for a service that does not advertise variables (`capabilities.variables`). Secrets are written with
DuckDB's own statements: `CREATE [OR REPLACE] PERSISTENT SECRET … IN corp`, `DROP PERSISTENT SECRET … FROM
corp`. Any DuckDB function that reads secrets (`duckdb_secrets()`, `which_secret(path, type)`) sees the
service's, with `storage = 'corp'`.

## The audit

With `tresor_audit_level` other than `off` and DuckDB's logging on for the `tresor` type
([Concepts](./concepts.md#what-tresor-did-audit-and-traces)), each event is a row of
`duckdb_logs_parsed('tresor')` with these columns:

| Column | |
| --- | --- |
| `kind` | `login`, `logout`, `lookup`, `refresh`, `write`, `drop`, `annotate`, `grant`, `revoke`, `session_grant` |
| `outcome` | `ok`, `none` (an `IF [NOT] EXISTS` that changed nothing), `denied`, `error` |
| `reason_code` | on `denied` / `error`: `no_verb`, `not_found`, `actor_not_allowed`, `mint_refused`, `unauthenticated`, `service_unavailable`, `transport`, `invalid`, `no_grant`, `other` |
| `reason` | tresor's own words, bounded: never an exception's or the service's text |
| `service`, `host` | the catalog (`corp`) and the service it names |
| `login` | the login's flow |
| `principal`, `user` | who the call was for: the login's subject, and on a duckdb-acl node the session's user |
| `acl_session`, `correlation_id`, `traceparent` | on a duckdb-acl node: the session, and the statement's correlation id and trace context |
| `secret`, `secret_type` | the secret's name and type, never its material |
| `cached` | always false in a row: a lookup served from tresor's memory is counted, not logged |
| `dynamic` | the secret is generated per caller |
| `target` | `grant` / `revoke`: the `role:` or `group:` principal |
| `duration_us` | the service calls' time; NULL when none was made |
| `detail` | what kind of event within its `kind`: for `login` e.g. `remembered`, `web_login`, `web_token`, `act_for_sessions`, `resumed`, `resumed_other`; for `logout` `logoff` or `logoff_revoked` (none at DETACH); for `session_grant` `obtained`, `failed`, `revoked`, `rejected`, `expired` |
| `seq` | per instance, increasing, in delivery order |

The same events reach an exporter through the `tresor_audit` contract (acl-otel), with the same fields.
