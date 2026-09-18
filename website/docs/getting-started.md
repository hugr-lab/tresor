---
sidebar_position: 2
title: Getting started
---

# Getting started

:::caution Target design
This page describes the interface tresor is being built to. Today only the `tresor` ATTACH type is
registered.
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

The login lasts for the session; the token refreshes by itself.

```sql
FROM corp.whoami();      -- issuer, subject, roles, token expiry
FROM corp.secrets();     -- the secrets your role may use, with what you may do to each
```

## As a service: attach with a secret

A process without a person logs in with its own credential, kept in a local secret of tresor's type:

```sql
CREATE SECRET corp_login (
    TYPE tresor,
    SCOPE 'secrets.corp.example',
    FLOW 'client_credentials', CLIENT_ID '…', CLIENT_SECRET '…'
    -- or FLOW 'private_key_jwt', PRIVATE_KEY '…'
    -- or FLOW 'federated', ASSERTION_FILE '/var/run/secrets/tokens/…'   (Kubernetes, Azure workload identity)
);
ATTACH 'tresor:secrets.corp.example' AS corp;   -- the secret is found by its SCOPE
```

## Use the secrets

Secrets from the service take part in DuckDB's ordinary lookup — nothing names tresor:

```sql
ATTACH '' AS crm (TYPE mssql, SECRET crm_ro);
FROM 's3://lake/sales/*.parquet';
```

## Store and manage

```sql
CREATE PERSISTENT SECRET lake_rw IN corp (TYPE s3, KEY_ID '…', SECRET '…', SCOPE 's3://lake');
CALL corp.annotate_secret('lake_rw', 'Read-write on the lake bucket, owned by the data team');
CALL corp.grant_secret('lake_rw', principal := 'role:data_team', verbs := ['use']);
DROP PERSISTENT SECRET lake_rw FROM corp;
```

Whether each of these is allowed is decided by the service from your role.

## Detach

```sql
DETACH corp;   -- logs out; the service's secrets leave the lookup
```
