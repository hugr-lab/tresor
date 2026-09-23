---
sidebar_position: 3
title: Concepts
---

# Concepts

## The attached catalog is three things

`ATTACH 'tresor:…' AS corp` creates one name with three roles:

1. **A secret storage named `corp`** in DuckDB's secret manager. Its secrets take part in every
   lookup; `CREATE PERSISTENT SECRET … IN corp` stores into the service and `DROP PERSISTENT SECRET …
   FROM corp` deletes there. `SET default_secret_storage = 'corp'` makes the service the default for
   persistent secrets.
2. **A catalog of functions** — `corp.secrets()`, `corp.whoami()`, `corp.grants(…)`,
   `corp.delegations(…)`, `corp.annotate_secret(…)`, `corp.grant_secret(…)`, `corp.add_delegation(…)` —
   the view and the management surface.
3. **A login.** The identity the attach established is what every call to the service carries.

Several services can be attached at once; each is its own storage and its own catalog.

## Lookup

DuckDB picks a secret by how well its scope matches the path in hand. tresor keeps the list of
secrets your role may use (names, types, scopes — no material) and answers DuckDB's lookup from it;
the **material is fetched only when a secret matches**, and cached until it expires. Secrets the
service marks *dynamic* are generated per request with an expiry — short-lived credentials — and S3
secrets among them are refreshed through httpfs's own `REFRESH auto` when they run out.

## What your role may do

The service decides, per secret, which of these verbs you hold — and shows them in
`corp.secrets()`:

| Verb | Meaning |
| --- | --- |
| `create` | create new secrets (service-wide, possibly limited to name patterns) |
| `use` | receive the material yourself |
| `update` / `delete` | replace or remove |
| `annotate` | describe |
| `grant` | give or take verbs from others |
| `delegate` | set up delegation |

## Delegation

A server — a DuckDB node behind a gateway, a data platform — sometimes works **on behalf of** a
user: reading an API with the user's rights, writing to the user's area of object storage. A
secret is **not delegated** unless the service has a rule for it. A delegation rule says which
servers may act, for which users, how:

- **`user`** — the service issues a credential of the user's own (a tagged STS session, a temporary
  database user, a token on the user's behalf): the resource sees the person.
- **`shared`** — the server receives a shared secret, only to act for that user, and every use is
  audited under the user's name. The user needs no `use` verb: they can **use a secret without ever
  seeing it**, which is only possible through a server.

A server acting for a user never adds its own authority: every call carries the user's identity,
and the service checks the user's rights, the rule, and that the server may act for users at all.

### On a duckdb-acl node

A node running [duckdb-acl](https://github.com/hugr-lab/duckdb-acl) attaches the service **as
itself** and acts for the users whose sessions it serves:

```sql
CREATE SECRET node (TYPE tresor, FLOW client_credentials, ISSUER 'https://idp.example/realms/corp',
                    CLIENT_ID 'acl-node', CLIENT_SECRET '…');
ATTACH 'tresor:secrets.example' AS corp (SECRET node, ACT_FOR_SESSIONS true);
```

When a user's acl session opens, tresor:
1. exchanges the session's token at the identity provider for one meant for the service;
2. trades that token for a delegation grant;
3. uses the grant for every statement of the session: secret lookups, `corp.secrets()`,
   `corp.whoami()` (which answers the user, with `actor` = the node);
4. revokes the grant when the session ends.

Under a session, a secret lookup is served **the user's delegated secret** wherever one covers the
path. That is whatever a rule lets this node use for them: an http API, another acl node through
quack. Every other path is served **the node's own secret**, which is what its catalogs (ducklake,
iceberg, attached databases) read. A path that both cover gets the delegated one. If the grant is
still pending, lookups wait up to `SESSION_GRANT_WAIT` seconds (10 by default). Without a usable
grant, only the node's secrets serve. Explicit calls (`corp.whoami()`, `corp.secrets()`, writes) are
always the user's, through the grant, or fail with the reason.

This applies only to statements duckdb-acl runs under a session, through a service-login attachment.
Everywhere else the ordinary rule holds: a person's attachment serves that person's secrets, and a
node's own work is served the node's.

| Option | Default | |
| --- | --- | --- |
| `ACT_FOR_SESSIONS` | `false` | act for duckdb-acl's sessions |
| `EXCHANGE` | `'token_exchange'` | `'token_exchange'` (RFC 8693: Keycloak, Okta, …) or `'on_behalf_of'` (Entra) |
| `EXCHANGE_SCOPE` | — | the scope asked for; required for `on_behalf_of` (`api://…/.default`) |
| `EXCHANGE_AUDIENCE` | the discovery's | the audience users' tokens are exchanged for; without it, the discovery's is accepted only if the node's own token carries it |
| `SESSION_GRANT_WAIT` | `10` | seconds a session's statement waits for its grant |

The identity provider must allow the node's client to exchange tokens. In Keycloak (standard token
exchange):
- set `standard.token.exchange.enabled` on the node's client;
- give the users' client an audience mapper that names the node's client;
- give the node's client an audience mapper that names the service's client.

The test realm in `server/testdata/keycloak` has all three. With Entra, the token's `iss` must equal
the issuer the node logs in with: v1 tokens (`https://sts.windows.net/<tenant>/`) against a v2
issuer are refused as "from another issuer".
