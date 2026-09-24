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
   `corp.annotate_secret(…)`, `corp.grant_secret(…)`, `corp.revoke_secret(…)` — the view, and the
   management surface for administrators.
3. **A login.** The identity the attach established is what every call to the service carries.

Several services can be attached at once; each is its own storage and its own catalog.

## Lookup

DuckDB picks a secret by how well its scope matches the path in hand. tresor keeps the list of
secrets your role may use (names, types, scopes — no material) and answers DuckDB's lookup from it;
the **material is fetched only when a secret matches**, and cached until it expires. Secrets the
service marks *dynamic* are generated per request with an expiry — short-lived credentials — and S3
secrets among them are refreshed through httpfs's own `REFRESH auto` when they run out.

## What your role may do

Two kinds of callers, and one rule each:

- **Users use.** You use exactly the secrets an administrator granted to one of your roles or
  groups (`role:…`, `group:…` from your token). You do not create or share secrets in the service:
  keep your own in your DuckDB (`CREATE SECRET`). `corp.secrets()` shows `permissions = [use]`.
- **Administrators manage.** They create, change, annotate and delete secrets, and grant `use` to
  roles and groups. An administrative role does not imply `use`: to use a secret, an administrator
  grants it to one of their own roles, like anyone else.

Nobody but an administrator can put a secret where your lookups find it, so nobody can plant one on
your paths.

## Acting for users

A server (a DuckDB node behind a gateway, a data platform) runs statements **for** its users. It
holds a role of its own, and an administrator grants that role what the server serves: its lake,
its catalogs, its databases. When a user's session opens, the server obtains a **delegation grant**
for them. Through it:
- **the user gets exactly the server's secrets** for the statements the server runs for them, and
  nothing more. The server never adds the user's rights to its own, nor its own to the user's
  beyond what an administrator granted it;
- **an administrator can manage through the server:** only a user who is an administrator, and only
  what the service's policy lets that server pass on.

### A token for the caller

Some secrets are a token rather than a stored credential. Examples are an http API that authorises
per user, or another acl node through quack:

```sql
ATTACH 'tresor:secrets.example' AS corp;
ATTACH 'quack:corp.duck' AS remote (TYPE quack);   -- its secret comes from corp, with your own token
```

An administrator stores such a secret with the service's `token_exchange` provider and the
downstream audience. You then get a fresh token of **your own** for it, minted by the identity
provider. Through a node acting for your session, you still get a token of your own, never the
node's. tresor caches it until shortly before it expires.

### On a duckdb-acl node

A node running [duckdb-acl](https://github.com/hugr-lab/duckdb-acl) attaches the service **as
itself** and acts for the users whose sessions it serves:

```sql
CREATE SECRET node (TYPE tresor, FLOW client_credentials, ISSUER 'https://idp.example/realms/corp',
                    CLIENT_ID 'acl-node', CLIENT_SECRET '…');
ATTACH 'tresor:secrets.example' AS corp (SECRET node, ACT_FOR_SESSIONS true);
```

Load duckdb-acl before this ATTACH: `ACT_FOR_SESSIONS` is refused where nothing publishes acl sessions.

When a user's acl session opens, tresor:
1. exchanges the session's token at the identity provider for one meant for the service;
2. trades that token for a delegation grant;
3. uses the grant for every statement of the session: secret lookups (the node's secrets, served for
   the user's statement), `corp.secrets()`, `corp.whoami()` (which answers the user, with `actor` =
   the node), and an administrator's management;
4. revokes the grant when the session ends.

A statement under a session never runs with the node's bare identity: always through the session's
grant, or not at all. If the grant is still pending, lookups wait up to `SESSION_GRANT_WAIT` seconds
(10 by default). If the exchange or the grant failed, lookups in `corp` find nothing and explicit
calls fail with the reason.

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

## What tresor did: audit and traces

tresor records what it did as events: logins and logouts, secret lookups and refreshes, writes, drops,
annotations, grants and revocations, and on a duckdb-acl node each session's delegation grant
(obtained, failed, revoked, rejected, expired). An event names:
- the service and the caller;
- the secret (never its material);
- the outcome, and for a refusal a bounded reason code;
- the time the service took.

It never carries a token, a session handle, a grant id or a statement's text. The events go to two
places, each off unless you ask for it:

- **DuckDB's log.** `tresor_audit_level` is `off` (the default), `denied` (refusals and failures) or
  `all`. DuckDB keeps a row only while its own logging is on for the `tresor` type:

  ```sql
  SET tresor_audit_level = 'all';
  CALL enable_logging('tresor');
  SELECT kind, outcome, secret, reason_code, duration_us FROM duckdb_logs_parsed('tresor');
  ```

  A row written for a statement names its connection and query, like any DuckDB log row. A lookup
  served from tresor's memory is not logged: a scan asks for its secret once per file.
- **The `tresor_audit` contract** (duckdb-ext-common), for an exporter loaded beside tresor. On a
  duckdb-acl node, [acl-otel](https://github.com/hugr-lab/acl-otel) turns the events into
  OpenTelemetry logs, spans and metrics. With no exporter loaded, no event is even composed.

**Traces.** Under an acl session, an event carries the statement's `traceparent` and correlation id,
as duckdb-acl publishes them. An exporter places tresor's work in the trace of the statement that
caused it. tresor also sends the `traceparent` to the service ([protocol, Tracing](./protocol.md#tracing)),
so a service that traces continues the same trace.

