---
slug: /
sidebar_position: 1
title: tresor
---

# tresor

**One OIDC login, role-based secrets for DuckDB.** tresor is a DuckDB extension that attaches your
organisation's secrets service. You log in once through your identity provider — Keycloak, Okta,
Entra ID, any OIDC provider — and the secrets your role may use appear in DuckDB's own secret
manager: `ATTACH … (SECRET crm_ro)`, `FROM 's3://lake/…'` and every other secret consumer just work.

```sql
ATTACH 'tresor:secrets.corp.example' AS corp;   -- browser login, once

FROM corp.secrets();                                   -- what your role may use
ATTACH '' AS crm (TYPE mssql, SECRET crm_ro);          -- a secret from the service
FROM 's3://lake/sales/*.parquet';                      -- found by scope, like any secret
```

:::caution Status
tresor is being built. This site describes the design it is built to; pages mark what exists.
Attaching a service, logging in and `corp.whoami()` work today. Next come the secrets themselves:
lookup, then writes.
:::

## What it is

- **A client, not a vault.** Where and how secrets are stored is the service's business. tresor
  speaks an open protocol — [`duckdb-secrets/1`](./protocol.md) — that a service in any language
  implements.
- **The ATTACH is the whole setup.** DuckDB loads an installed extension by the prefix of the path it
  is asked to attach, so `ATTACH 'tresor:…'` is the only statement a user writes: discovery, login and
  mounting happen inside it.
- **Your role decides, the service enforces.** You use what an administrator granted your roles —
  the same through the CLI as through a server acting for you, which serves you its own grants.
- **Management is SQL, for administrators.** `CREATE PERSISTENT SECRET … IN corp` stores into the
  service; grants and annotations are functions of the attached catalog.

## Where to next

- [Getting started](./getting-started.md) — the first attach, for a person and for a service.
- [Concepts](./concepts.md) — the attached catalog, lookup, persistence, acting for users.
- [Protocol](./protocol.md) — the specification a secrets service implements.
- [Security model](./security.md) — what a role can and cannot protect, and why delegation matters.
