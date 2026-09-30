# Spec 015: a node's bootstrap — acting for sessions on a live catalog, a managed identity as the assertion

- **Status**: implemented
- **Date**: 2026-09-30
- **Author**: hugr lab
- **Asked by**: the owner, through duckdb-acl's session (the platform node bootstrap)

## Summary

A node installs everything else from an authenticated extension repository; tresor is the one public
extension, and its ATTACH is what gives the node the repository's http secret. So the node attaches
tresor **before** duckdb-acl is loaded — and today it must then DETACH and ATTACH again with
`ACT_FOR_SESSIONS`. Two changes remove that and the node's last secret:

1. `CALL corp.act_for_sessions(...)` turns acting for duckdb-acl's sessions on for an attached catalog.
2. `ASSERTION_SOURCE 'azure_managed_identity'`: the node's managed identity is the federated credential of
   its app registration, so a node acting for users (On-Behalf-Of) holds no secret at all.

The node's sequence:

```sql
INSTALL tresor; LOAD tresor;
CREATE SECRET node (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'federated',
    CLIENT_ID '<app registration>', ISSUER 'https://login.microsoftonline.com/<tenant>/v2.0',
    OAUTH_SCOPE 'api://duckdb-secrets/.default', ASSERTION_SOURCE 'azure_managed_identity');
ATTACH 'tresor:secrets.corp.example' AS corp (SECRET node);
-- the repository's secret is now in DuckDB's lookup
INSTALL acl FROM '<repository>'; LOAD acl;   -- acl_otel, ...
CALL corp.act_for_sessions(exchange := 'on_behalf_of', exchange_scope := 'api://duckdb-secrets/.default');
```

## Design

### `act_for_sessions`

```sql
CALL corp.act_for_sessions(
    exchange := 'token_exchange' | 'on_behalf_of',   -- as ATTACH's EXCHANGE
    exchange_scope := VARCHAR,                       -- EXCHANGE_SCOPE
    exchange_audience := VARCHAR,                    -- EXCHANGE_AUDIENCE
    session_grant_wait := INTEGER)                   -- SESSION_GRANT_WAIT (seconds)
-- one row: service, exchange, audience, scope, changed
```

- A table function of the tresor catalog, in its main schema, like `whoami()`.
- The checks are ATTACH's `ACT_FOR_SESSIONS` ones, made at the call. They are one function
  (`ActingOptions`), used by both:
  - duckdb-acl is loaded and publishes its sessions (ACLC 2);
  - the login is a client at the identity provider (`client_credentials` or `federated`);
  - the node pins the exchange's audience:
    - `EXCHANGE_AUDIENCE`, or the discovery's audience, and that only when the node's own token is
      issued for it;
    - with the discovery's `audience_parameter`, `EXCHANGE_AUDIENCE` is required;
    - On-Behalf-Of needs a scope.
- **One way.** There is no disable: DETACH (or a restart) ends it, as it ends an ATTACH's.
- **Idempotent.** The same options again: `changed = false`. Other options: an error; DETACH to change.
- **Never under an acl session.** Like `tresor_logoff`, it is refused when the statement runs under a
  duckdb-acl session, or when acl's connection contract cannot tell. duckdb-acl also puts
  `act_for_sessions` in its never set (by name, in any catalog).
- **Audited**: TRSA kind `login`, detail `act_for_sessions`. The contract's layout is unchanged.
- **Before the call**, a statement under an acl session is refused ("does not act for duckdb-acl
  sessions"), as for a plain ATTACH. Fail closed.
- `ATTACH … (ACT_FOR_SESSIONS true, …)` goes the same way: the same checks, and the actor started by the
  catalog.

**The exchange's audience lives in the actor, not in the session.** An ATTACH with `ACT_FOR_SESSIONS`
used to overwrite the session's `audience` with the pinned one. The session's own renewals then asked for
it too, when the discovery's `audience_parameter` was on. Now:
- the session keeps the discovery's audience for its own token;
- the actor passes the pinned audience to each exchange (`ExchangeForService(…, audience)`).

### `ASSERTION_SOURCE 'azure_managed_identity'`

- `FLOW 'federated'` takes the platform's managed identity token as its client assertion:
  - `ASSERTION_AUDIENCE` defaults to `api://AzureADTokenExchange`;
  - `IDENTITY_CLIENT_ID` names a user-assigned identity; without it, the system-assigned one.
- The token is asked for at each mint and each exchange; the platform caches and rotates it.
- It is sent only when it is a JWT for `ASSERTION_AUDIENCE`, as the `managed_identity` flow checks its own.
- It is a client at the identity provider, so it can act for sessions, On-Behalf-Of included.
- whoami's `login` is `federated`.

## Enforcement & security

- Only the node's own connection enables acting; an acl session can neither call it nor reach it
  (duckdb-acl's never set, and tresor's own refusal).
- Enabling cannot widen what an ATTACH could do: the same checks, the same pinned audience, the same
  grants per session.
- The managed identity's token never goes anywhere but the identity provider's token endpoint, as a
  client assertion, and only for the audience the secret names.

## Testing

- `test/sql/attach/act_for_sessions.test` (the fake service, acl_stub):
  - refused under an acl session;
  - refused before a publisher is loaded;
  - refused for a person's login;
  - enabled, then `changed = false` for the same options, and an error for other options;
  - a session's statement refused before the call and served through its grant after it.
- `test/sql/attach/managed_identity.test` (the fake IMDS):
  - `ASSERTION_SOURCE 'azure_managed_identity'` logs in as a federated client;
  - a token for another audience is refused.
- `test/acl/actor.sql` against real duckdb-acl: the late call on a catalog attached before acl.

## Alternatives considered

- **A setting** (`SET tresor_act_for_sessions`): global, and it would have no catalog to check.
- **Re-attaching under the hood**: a DETACH drops the secrets from the lookup mid-bootstrap, and the
  whole point is not to.
