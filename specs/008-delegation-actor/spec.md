# Spec 008: tresor as the actor — a duckdb-acl session's secrets are its user's

- **Status**: implemented
- **Date**: 2026-09-23
- **Author**: VGSML (with Claude)

## Summary

On a duckdb-acl node, the node attaches the secrets service **as itself** (a service login) and runs
many users' statements through acl sessions. With this spec, a statement that runs under an acl
session uses **that session's user's** secrets, never the node's:
1. When a session opens, tresor exchanges the user's token at the IdP for one meant for the secrets
   service (RFC 8693, or Entra's On-Behalf-Of).
2. It trades that token for a **delegation grant** (spec 007).
3. Every service call made for the session's statements (secret lookups, `corp.secrets()`,
   `corp.whoami()`, writes, management) carries the grant.
4. When the session ends, the grant is revoked.

It is opt-in per ATTACH (`ACT_FOR_SESSIONS`). Without it, statements under an acl session get
nothing from the service, rather than the node's secrets.

## Problem

- **The confused deputy.** Today tresor on a node answers every lookup with the node's identity.
  A user connected through an acl door (quack, Flight SQL) who reads `s3://lake/…` would be served
  with the node's credentials. The rule is that a server never adds its own authority.
- **The audience rule.** The token acl verified was issued *for the node* (its `aud`). Sending it to
  the secrets service would break "a token goes only to its audience". It must be exchanged at the
  IdP (duckdb-ext-common spec 004, `v0.3.0`).
- **Where the session is.** Nothing told tresor which session a statement belongs to, or when
  sessions open and close. duckdb-acl's `acl_connection` contract (duckdb-ext-common spec 005,
  `v0.4.0`; duckdb-acl spec 078) now does.

## Design

### SQL

```sql
CREATE SECRET node (TYPE tresor, FLOW client_credentials, ISSUER 'https://idp/realms/corp',
                    CLIENT_ID 'acl-node', CLIENT_SECRET '…');
ATTACH 'tresor:secrets.corp' AS corp (SECRET node, ACT_FOR_SESSIONS true);
```

| Option | Default | Meaning |
| --- | --- | --- |
| `ACT_FOR_SESSIONS` | `false` | act for acl sessions: exchange, grant, use, revoke |
| `EXCHANGE` | `'token_exchange'` | `'token_exchange'` (RFC 8693) or `'on_behalf_of'` (Entra) |
| `EXCHANGE_SCOPE` | (none) | the scope asked for at the exchange; required for `on_behalf_of` (`api://…/.default`) |
| `SESSION_GRANT_WAIT` | `10` | seconds a session's first statement waits for its grant |

- **A service login only.** `ACT_FOR_SESSIONS` needs a `client_credentials` login (`SECRET` of flow
  `client_credentials`). The exchange is made as that client, and the service's actor policy names
  it (`client:<id>`).
- **The exchange's audience** is the `audience` of the chosen issuer in the service's discovery,
  and `scope` is `EXCHANGE_SCOPE`. With neither, the ATTACH is refused.

### The session's life

tresor registers a `SessionObserver` in acl's `AclSessionHooks` when the catalog activates, and
removes it on DETACH. Load order does not matter: acl reads the list at every call.

1. **`OnSessionOpen(info, token)`** returns at once. It copies the token into a job for tresor's
   own worker threads (2 per attached catalog) and marks the session *pending*.
2. **The worker:**
   - It checks `info.token_issuer` against the actor's own issuer. A token from another IdP cannot
     be exchanged with this client, so the session *fails* ("the session's token is from another
     issuer").
   - It exchanges the token (`oidc::TokenExchange` / `oidc::OnBehalfOf`).
   - It sends `POST /v1/delegations {subject_token, ttl}`. `ttl` is the session's remaining
     lifetime (`expires_at - now`, when acl knows it), and the service caps it.
   - Then it **wipes** both tokens (the user's and the exchanged one). The grant id and its
     `expires_at` are kept, and the session is *ready*.
   - Any failure marks the session *failed*, with a reason that names the step, never a token.
3. **`OnSessionClose(id, reason)`:**
   - a *ready* session's grant is revoked (`DELETE /v1/delegations/{id}`) on a worker;
   - a *pending* one is marked closed, and its grant is revoked as soon as it arrives;
   - an unknown id is ignored (a session opened before the ATTACH).

   The session's cached list and material go with it.
4. **DETACH** stops the workers: queued exchanges are dropped and their tokens wiped. The grants
   still held are revoked before the login's tokens are dropped.

### Which identity a call uses

Every service call tresor makes for a statement first asks acl's `AclConnection` of the statement's
connection (through the transaction's `ClientContext`):

| The statement runs… | `ACT_FOR_SESSIONS` | The call |
| --- | --- | --- |
| under no acl session (or with no connection) | any | as the node: its own login, as before |
| under session S, whose grant is ready | on | as the node **with `Delegation: <grant>`**: the service answers as S's user |
| under S, grant pending | on | waits up to `SESSION_GRANT_WAIT`, then as above or refused |
| under S, grant failed, expired, or refused by the service (401) | on | refused |
| under S | off | refused: "corp does not act for acl sessions" |
| acl's connection state stamped with another contract version | any | refused (it cannot tell whose statement this is) |

**Refused** means:
- **Lookups** (`LookupSecret`, `GetSecretByName`, `duckdb_secrets()`) find nothing in `corp`. They
  never throw, because a lookup walks every storage, and a query that does not need `corp` must
  not fail on it.
- **Explicit calls** (`corp.whoami()`, `corp.secrets()`, writes, the management functions) throw
  with the reason.

**Caches.** Each acl session gets its own descriptor list and material cache, separate from the
node's. They are dropped when the session closes, and a grant's material is never served to
another session or to the node.

### Protocol

No change to requests or responses. The protocol page's *Delegation* section gains a
non-normative note: an actor revokes a grant when the session it was made for ends, and the grant's
`ttl` follows the session's lifetime.

## Enforcement & security

- **Never the node's authority for a user.** Every path from a statement under an acl session
  either carries the session's grant or finds nothing. There is no fallback to the node's view.
- **Tokens.** The user's token lives from `OnSessionOpen` to the end of the exchange, the exchanged
  one until the grant arrives. Both are then wiped, never logged, and never in an error. The user's
  token is sent only to the IdP that issued it (its issuer is checked), and the exchanged one only
  to the service (its audience).
- **Grant ids** are bearer credentials when held together with the node's token. They are kept in
  memory, never logged, never shown by any function, and revoked at session end.
- **Bounded.** `OnSessionOpen` never blocks on the network, so acl's connect waits only for a copy.
  A statement waits at most `SESSION_GRANT_WAIT` for a grant.
- **Contract mismatch.** An acl built from another `acl_connection` version: every statement is
  refused, since tresor cannot tell whose statement it is. No observer is registered on mismatched
  hooks.

## Testing

- **`test/extension/acl_stub`**, a test-only extension linked into the test build
  (`TRESOR_TEST_HTTPFS=1`, beside httpfs). It plays acl's side of the contract:
  - `acl_stub_open(session_id, token, issuer, expires_in)` calls the observers;
  - `acl_stub_close(session_id, reason)` closes a session;
  - `SET acl_stub_session = '<id>'` publishes the session at each statement's `QueryBegin` and
    withdraws it at `QueryEnd`, as acl does.
- **The fake** grows:
  - an RFC 8693 exchange at its IdP, for the `etl` client;
  - `POST /v1/delegations`, `DELETE /v1/delegations/{id}`, and the `Delegation` header: under a
    grant it answers as the user, and lists only the secrets that a rule delegates to the actor for
    that user;
  - counters the tests read back.
- **`test/sql/attach/actor.test`:**
  - `ACT_FOR_SESSIONS` refused without a service login, and with neither audience nor scope;
  - a session's `corp.whoami()` answering the user with `actor`;
  - a lookup under the session finding the user's delegated secret, and the node's own secret not
    found;
  - the node's view unchanged outside the session;
  - a session from another issuer: refused, with the reason;
  - a failed exchange;
  - close → the grant revoked (the fake counts it);
  - without `ACT_FOR_SESSIONS`: nothing under a session;
  - DETACH revoking the grants still held.
- **Keycloak end to end** (`test/sql/reference_server/actor.test`):
  - a real user token from Keycloak (`alice`, password grant for the test);
  - a real exchange at Keycloak (the realm gains the `acl-node` client, standard token exchange and
    the audience mappers);
  - a real grant from the reference server, used through the stub.
- **With duckdb-acl itself:** `scripts/ci/test_keycloak.sh` runs `test/acl/actor.sql` when
  `TRESOR_ACL_EXTENSION` names an `acl.duckdb_extension` built at this repository's duckdb commit. It
  is a CLI script, because the statements under the session need the handle `acl_session_open`
  returns. It uses acl's real `acl_session_open`, a virtual table function over `node.whoami()` and
  `which_secret`, and `acl_session_close`. It checks that:
  - the statements run as alice with `actor` = the node;
  - the delegated secret is found;
  - the reference server logged the grant created and revoked.

  It passed locally against duckdb-acl `3a5fdb3`. Its CI job is a follow-up.

### As built

- **Keycloak (26.4, standard token exchange) needs three things,** all in the test realm:
  - `standard.token.exchange.enabled` on the node's client (`acl-node`);
  - an audience mapper naming `acl-node` on the users' client (`acl-door`), because the subject
    token's `aud` must include the exchanger;
  - an audience mapper naming the service on `acl-node`. For that, the service's audience is a
    client (`duckdb-secrets`, with no flows): Keycloak refuses an audience that is not a client of
    the realm ("Requested audience not available").
- **Under duckdb-acl,** a principal can call only what acl's policy admits. tresor's catalog
  functions and `which_secret` are refused under a session ("table function … is not allowed")
  unless an acl virtual function wraps them. Secret lookups made by the functions acl admits (a
  scan of `s3://…`, `read_json('https://…')`) go through the grant.
- **A 401 under a grant is the grant.** `TresorSession::Call` renews the node's login and retries
  once. If a request carrying `Delegation` is still refused after that, the 401 goes back to the
  caller, which marks the session's grant rejected, instead of being read as "log in again".

## Alternatives considered

- **Exchanging on the first statement** instead of at open. That keeps the user's token past the
  observer call, which acl's contract forbids.
- **Falling back to the node's identity** while a grant is pending or failed. That is the confused
  deputy.
- **Throwing from lookups under a refused session.** Every query that touches any secret would
  fail, including queries that use none of `corp`'s. Explicit calls throw; lookups find nothing.
- **One exchange per user instead of per session.** Grants are per session in acl's model, and a
  shared one could not be revoked when a single session ends.

## Follow-ups

- A CI job running `test/acl/actor.sql` with duckdb-acl's own `acl.duckdb_extension` (an artifact of
  its distribution build at the pinned duckdb commit).
- tresor's audit hook (`tresor_audit.hpp`): grant created, used, revoked, and refused.
