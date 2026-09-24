# Spec 010: a token for the caller — secrets the service mints per caller, a session's user included

- **Status**: implemented
- **Date**: 2026-09-24
- **Author**: VGSML (with Claude)

## Summary

Some secrets must carry **the caller's own token**, not a shared credential:
- an http API that authorises per user (`bearer_token`);
- another duckdb-acl node reached through quack (`TOKEN`), which then applies its own policy to the
  same person.

An administrator stores such a secret **without a token**: `provider: token_exchange`, and the
downstream `audience`. On every read, the service answers with a fresh access token minted **for the
caller** at the identity provider, as a dynamic secret (`expires_at`):
- **a user reading directly** (their own `ATTACH 'tresor:…'`): the service exchanges the token they
  called with, on demand;
- **a server under a delegation grant** (a duckdb-acl session): a token for **the grant's user**,
  never the server's. At the grant's exchange, the service exchanges the user's token for each
  audience the server may use **with a refresh token**, keeps that with the grant (in memory), and
  renews the access token from it while the user's IdP session lives;
- **a service reading as itself:** its own token, exchanged the same way.

Nothing on the node holds a user's token. The administrator decides where a user's token may go:
the secret's audience, and the grants of `use` (spec 009).

## Why a refresh token for grants, and not for direct reads

- **A direct reader** presents a live token of their own on every call; tresor renews its login.
  Exchanging that token when the minted one expires needs nothing kept.
- **Under a grant** there is no live user token after the grant is made. acl hands the node the
  session's token once, and the node must forget it. The exchanged token the service sees at the
  grant lives minutes. Only a refresh token can mint for the user an hour later. It is also bound
  to the user's IdP session: a logout or an admin's revocation ends it, and with it every token
  minted for them.

## Design

### The secret

```json
PUT /v1/secrets/corp_duck      (an administrator)
{"type": "quack", "provider": "token_exchange", "scope": ["quack:corp.duck"],
 "params": {"audience": "acl-node"}, "redact_keys": []}
```

- **`provider: token_exchange`** marks a minted secret. `params.audience` is required;
  `params.scope` is optional. The other params are passed through as they are (http's
  `extra_http_headers`, for instance).
- **Types.** Only types whose token parameter the service knows are accepted: `http`
  (`bearer_token`) and `quack` (`token`). Any other type gets `422 invalid_secret`.
- **Descriptor and material.** The descriptor says `dynamic: true`. The material has the token
  parameter filled in, listed in `redact_keys`, with `expires_at` set to the token's `exp`.

### Who the token is for

- **`GET /v1/secrets/{name}` with `use`, and no grant:** the caller's own bearer token is exchanged
  (RFC 8693, as the service's own client at the token's issuer) for `audience` (and `scope`). The
  result is cached per (caller, secret) until 30 s before `exp`.
- **Under a grant:**
  - `use` is the server's (spec 009);
  - the token is the **grant's user's**. At `POST /v1/delegations` the service finds the audiences of
    the `token_exchange` secrets the actor may use, and exchanges the subject token for each with a
    refresh token (`requested_token_type=refresh_token`). It keeps `{audience → access token, exp,
    refresh token}` with the grant, in memory only. A failure for one audience does not fail the
    grant; that secret's material is then refused with the reason;
  - a read serves the access token while it has 30 s left, and otherwise refreshes it (keeping a
    rotated refresh token). A refused refresh (`invalid_grant`: the user's IdP session is over) is
    `403 no_verb`, "the user's session at the identity provider has ended". A secret the node was
    granted after the grant was made is `403 no_verb`, "a new session picks it up";
  - the grant's revocation or expiry drops its tokens.

### The service's identity at the IdP

Each issuer the service mints for names the service's own confidential client:

```yaml
issuers:
  - issuer: https://idp/realms/corp
    exchange: {client_id: duckdb-secrets, client_secret_env: TRESOR_EXCHANGE_SECRET}
```

- With no `exchange`, a `token_exchange` secret of that issuer is refused at the read (`422`).
- The client secret comes from the environment, never from the YAML.
- The token endpoint comes from the issuer's discovery, which the verifier already does.

**Keycloak** (standard token exchange) needs:
- on the service's client: `standard.token.exchange.enabled`,
  `standard.token.exchange.enableRefreshRequestedTokenType: SAME_SESSION`, and an audience mapper
  for each downstream audience;
- on the node's client: the same refresh attribute. tresor asks for a refresh token at its own
  exchange (`with_refresh`, duckdb-ext-common v0.5.0) and drops it at once. Keycloak binds an
  exchanged token to the user's SSO session only when a refresh token is asked for, and the
  service's own exchange with refresh needs that session. An IdP that answers "requested_token_type
  unsupported" is asked again without it.

Checked live on Keycloak 26.4 (2026-09-23). Without the node's refresh request, the service's
exchange with refresh is refused ("creating a new session is needed"). With it, the service gets an
access token (`aud` = the downstream audience, `azp` = the service's client) and a refresh token
(1800 s) that renews.

### tresor

- **The node's exchange** (`TresorSession::ExchangeForService`) asks for `with_refresh`, falls back
  to a plain exchange on "requested_token_type unsupported", and wipes the refresh token either
  way.
- **Nothing else.** A minted secret is a dynamic secret. The cache honours `expires_at`, and under a
  session every lookup goes through the grant (spec 008).

### Protocol

Normative changes to `website/docs/protocol.md`:
- a dynamic secret's material may depend on **the caller**;
- under a delegation grant, per-caller material is the **grant's user's**, never the server's own.

`provider: token_exchange` is the reference server's convention, documented in
`reference-server.md`; the protocol keeps providers opaque.

## Enforcement & security

- **A user's token goes only where an administrator said:** the audience in the stored secret,
  bound further by the IdP's own mappers.
- **Refresh tokens stay in the service's memory, with the grant.** They are never on disk or in a
  log, and they die with the grant (a session's end revokes it, spec 008) or the user's IdP
  session.
- **No escalation.** Under a grant, material needs the server's `use` (spec 009), and the token
  minted is the user's, never the server's.
- **Nothing is logged.** No log line or error carries a token: the IdP's error descriptions are
  bounded, and the presented token is redacted from them.

## Testing

- **Go:** the test IdP gains a token endpoint (exchange with and without refresh, refresh,
  `invalid_grant`). Tests cover:
  - a minted secret's validation;
  - a direct read (the caller's token exchanged, the cache, `expires_at`);
  - a grant exchanging per audience;
  - reads under the grant for the user, a refresh after the clock moves, a refused refresh → `403`;
  - revocation dropping the tokens;
  - no `exchange` client → `422`.
- **tresor (fake):** the node's exchange asks for a refresh token and falls back when it is
  unsupported. The fake IdP records the request.
- **Keycloak end to end:**
  - the realm's `duckdb-secrets` becomes a confidential exchanger, with an `echo-api` audience;
  - `test/keycloak/echo.py` answers the `aud` and the user of the bearer token it receives;
  - a minted `http` secret scoped to it is read with `read_text`, both by alice directly and under
    alice's acl session through the node. Both give `aud = echo-api`, `user = alice`, never the
    node.

## Follow-ups

- Persisting refresh tokens (encrypted, with the store) so grants survive a restart. Today a restart
  ends them, as it ends acl sessions.
- More token-carrying types (`postgres` with a token as its password, …).
