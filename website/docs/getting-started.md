---
sidebar_position: 2
title: Getting started
---

# Getting started

:::caution Work in progress
Attaching, logging in, `corp.whoami()`, `corp.secrets()` and using the service's secrets work today.
*Store and manage* describes what comes next.
:::

## Install

```sql
INSTALL tresor;   -- from your organisation's extension repository, or community once published
```

No `LOAD` is needed: attaching a `tresor:` path loads the installed extension by itself.

## As a person: attach with a connection string

```sql
ATTACH 'tresor:secrets.corp.example' AS corp;
```

The service is named by host, optional port and base path — `tresor:host[:port][/base]` — and https
is implied. (Not a URL: given an `https://` path, DuckDB's ATTACH treats it as a remote database file,
requires httpfs and forces read-only before it ever looks at the type.)

tresor reads the service's discovery document (`/.well-known/duckdb-secrets`), learns which identity
provider to use, and logs you in:

- in a browser (authorization code + PKCE, redirected back to a local port), or
- with a device code, when there is no browser (SSH, containers) — the URL and code are printed.

`LOGIN 'auto'` (the default) opens a browser when it can: always on macOS and Windows, and on Linux
when a display is set. Otherwise it uses the device code. `LOGIN 'browser'` and `LOGIN 'device'`
choose explicitly. The environment variable `BROWSER` names the program to open the URL with. The
login waits up to `LOGIN_TIMEOUT` seconds (300 by default), and Ctrl-C cancels it.

If the service accepts more than one identity provider, name yours:

```sql
ATTACH 'tresor:secrets.corp.example' AS corp (ISSUER 'https://login.corp.example/realms/main');
```

The login lasts for the session and refreshes by itself. The tokens stay in memory and are never
written to disk, so a new DuckDB process logs in again.

```sql
FROM corp.whoami();      -- service, issuer, subject, roles, token expiry, what you may create, login flow
FROM corp.secrets();     -- the secrets you may see, with what you may do with each (no material)
```

The attached catalog `corp` holds functions only. It is read-only: you cannot create tables in it.

## As a service: attach with a secret

A process without a person logs in with its own credential, kept in a local secret of tresor's type:

```sql
CREATE SECRET corp_login (
    TYPE tresor,
    SCOPE 'tresor:secrets.corp.example',
    FLOW 'client_credentials', CLIENT_ID '…', CLIENT_SECRET '…',
    ISSUER 'https://login.corp.example/realms/main'   -- the IdP this credential belongs to
    -- optional: OAUTH_SCOPE 'api://duckdb-secrets/.default'
);
ATTACH 'tresor:secrets.corp.example' AS corp;                       -- the secret is found by its SCOPE
ATTACH 'tresor:secrets.corp.example' AS corp (SECRET corp_login);   -- or named
```

`SCOPE` is required and names the service: `tresor:<host>[:port][/base]`. It covers that host, any
path under it and, when it names no port, any port. A longer scope wins over a shorter one. A
`client_credentials` secret must name its `ISSUER`, so a service's credential only ever goes to its
own identity provider, whatever the secrets service's discovery says. `LOGIN 'browser'` or
`LOGIN 'device'` always logs you in as yourself, even when a service secret covers the host.

`FLOW 'token', TOKEN '…'` uses an access token the process already holds. It is not renewed: when it
expires, replace the secret and attach again. Private-key JWTs and federated workload identities
(Kubernetes, GitHub, Azure) are planned.

A `PERSISTENT` secret is written to DuckDB's local secret directory like any other. Keep service
credentials in a temporary secret when the process can create them from its environment.

## Development against a local service

Plain http is allowed only to this machine, and only when asked for:

```sql
ATTACH 'tresor:127.0.0.1:8080' AS dev (INSECURE_HTTP true);
```

## Use the secrets

Secrets from the service take part in DuckDB's ordinary lookup, and nothing names tresor. The attach
registers a secret storage under the catalog's name (`corp`):
- It matches scopes like any storage: the longest scope wins, and on a tie a local secret wins.
- It fetches a secret's material only when a lookup picks it, and keeps it in memory only. A static
  secret is kept for up to 5 minutes or until its version changes. A dynamic one is kept until
  shortly before it expires.
- A secret you may see but not `use` never matches, and is not found by name either.
- `DETACH corp` takes the secrets out of the lookup. So does an ATTACH that is rolled back.
- The service's own secrets of type `tresor` (logins) are listed in `corp.secrets()`, but never take
  part in the lookup: a service cannot plant how you log in elsewhere.

```sql
ATTACH '' AS crm (TYPE mssql, SECRET crm_ro);
FROM 's3://lake/sales/*.parquet';
FROM which_secret('s3://lake/sales/x.parquet', 's3');   -- which secret, from which storage
```

`duckdb_secrets()` lists the service's secrets too, but without material.

If the service becomes unreachable, the last list it gave still decides what it covers:
- A lookup that one of its secrets would win fails with the service's name, rather than quietly going
  without a credential.
- Other paths, `duckdb_secrets()` and your local secrets keep working.

A local secret with the same name as one of the service's makes `SECRET name` ambiguous (DuckDB's
rule). Name it with the storage, or rename one of them.

## Store and manage

```sql
CREATE PERSISTENT SECRET lake_rw IN corp (TYPE s3, KEY_ID '…', SECRET '…', SCOPE 's3://lake');
CREATE PERSISTENT SECRET IF NOT EXISTS lake_rw IN corp (…);     -- nothing if it exists
CREATE OR REPLACE PERSISTENT SECRET lake_rw IN corp (…);        -- needs `update` on it
SET default_secret_storage = 'corp';                           -- PERSISTENT without IN goes to the service

CALL corp.annotate_secret('lake_rw', 'Read-write on the lake bucket, owned by the data team');
CALL corp.grant_secret('lake_rw', 'role:data_team', ['use']);   -- one grant per principal, replaced
FROM corp.grants('lake_rw');
CALL corp.revoke_secret('lake_rw', 'role:data_team');
DROP PERSISTENT SECRET lake_rw FROM corp;
```

The service decides whether each of these is allowed, from your role. Some things to know:
- **Names** are stored in lower case, because DuckDB compares secret names case-insensitively.
- **Writes take effect immediately.** A `ROLLBACK` does not undo a `CREATE … IN corp`: the service
  has no transaction to join.
- **Secret types need their extension.** The type must be one DuckDB knows (an `s3` secret needs
  httpfs loaded), as for any storage. `allow_persistent_secrets = false` refuses persistent writes,
  the service's included.
- **Name the storage when dropping.** `DROP SECRET name` without `FROM corp` finds the secret by
  name, and by name tresor only finds secrets you may `use`. `FROM corp` needs only `delete`.

## Detach

```sql
DETACH corp;   -- logs out: the tokens are dropped (and, once secrets arrive, they leave the lookup)
```
