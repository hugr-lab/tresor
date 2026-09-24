---
sidebar_position: 5
title: Reference server
---

# The reference server

`server/` in tresor's repository is a small implementation of the [`duckdb-secrets/1`](./protocol.md)
protocol in Go. It exists for two reasons: tresor's end-to-end tests run against it next to a real
Keycloak, and a company writing its own service can read it to see the protocol working end to end.
It is **not meant for production**: one process, one encrypted file, no high availability.

## What it implements

- Discovery and `whoami`.
- Secrets: list, read, create/replace with preconditions (`If-None-Match: *`, `If-Match`), delete,
  annotate.
- Grants.
- Token verification against any number of OIDC issuers:
  - the signature against the issuer's JWKS;
  - `iss` (verbatim: an issuer ending in `/`, like Auth0 or Entra v1, works), expiry, and the
    audience;
  - asymmetric algorithms only.

- Tracing: the request log names the caller's `trace_id` and `parent_span_id` from a well-formed
  `traceparent`. It does not export spans; a production service would.
- Delegation: grant exchange, the `Delegation` header, and actor policy (tresor specs/009: under a
  grant a server uses its own grants for the user, and passes management through only for admins).

Dynamic secrets are implemented for one kind: a token for the caller (`token_exchange`, below). Issuers must be https unless they are on loopback: their signing keys are
fetched from them.

## Run it

```bash
cd server
go build -o tresor-server ./cmd/tresor-server
TRESOR_SERVER_KEY=$(openssl rand -base64 32) ./tresor-server -config server.yaml
```

```yaml
listen: 127.0.0.1:8443
public_url: http://127.0.0.1:8443        # what discovery calls `api`
# tls: {cert: server.crt, key: server.key}   # required unless listening on loopback
store:
  path: data/secrets.enc                 # AES-256-GCM; omit for memory only
  key_env: TRESOR_SERVER_KEY             # 32 bytes, base64
issuers:
  - issuer: https://login.corp.example/realms/main
    audience: duckdb-secrets             # the token's `aud` must contain it
    client_id: duckdb                    # the public client people log in with
    scopes: [openid]
    human_flows: [authorization_code, device_code]
    service_flows: [client_credentials, private_key_jwt]   # also: federated, managed_identity
    # audience_parameter: true           # Auth0: clients send audience=<audience> (tresor specs/013)
    roles_claim: realm_access.roles      # Keycloak; Entra/Okta: roles
    groups_claim: groups
    service: {claim: client_id}          # what marks a client-credentials token (see below)
policy:
  admins: [role:secrets_admin, client:etl]   # the only principals that manage secrets and grant use
  actors:                                    # servers that may act for users
    - {principal: client:acl-node, verbs: [use]}      # its own grants, for its users' statements
    - {principal: client:ops-node, issuer: https://login.corp.example/realms/main,
       verbs: [use, create, update, delete, annotate, grant]}   # admins may manage through it
```

## Who may do what

- **Principals.** Every caller is `subject:<issuer>|<sub>`, which is its identity. Its roles become
  `role:<name>` and its groups `group:<name>`.
- **Services.** A token is a service's only by its issuer's `service` rule: `claim` is present, and
  equals `equals` when that is set. The service then also gets `client:<name>`, taken from
  `client_claim` (default `azp`). No claim marks a service by convention. RFC 9068 puts `client_id`
  into every access token, a person's included. Without a rule, every caller is a person.
  - Keycloak: `{claim: client_id}`. The `service_account` scope sets it on client-credentials
    tokens only.
  - Entra: `{claim: idtyp, equals: app}`.
- **Verbs on a secret** (tresor specs/009). `use` comes only from a grant to one of the caller's
  roles or groups; grants name `role:` or `group:` principals, with `use` only. Admins
  (`policy.admins`) hold the management verbs on every secret, and create, but an admin role implies
  no `use`: an admin uses a secret when one of its roles is granted it. Users create and grant
  nothing.
- **`client:` names are shared.** They carry no issuer, so with several issuers a `client:etl` in a
  policy matches the `etl` of each.
- **Invisible secrets.** A secret you hold no verb on answers 404, exactly like one that does not
  exist.

## Delegation

- **Actors.** A server listed in `policy.actors`, optionally pinned to the issuer of its token,
  exchanges a person's token for a grant. The grant lives in memory only (8 h at most, and at most
  100 000 grants), is bound to that server, and is never logged.
- **Revocation.** Admins revoke by actor or subject (`DELETE /v1/delegations?actor=…`), and users
  revoke their own grants.
- **Under a grant:**
  - `use` is the **server's own** (its roles' grants), for the grant's user: nothing beyond what an
    admin granted the server;
  - a management verb (or `create`) passes only for a user who is an admin, and only if the actor's
    `verbs` list it;
  - everything else is `403 actor_not_allowed`.

## A token for the caller (`token_exchange`)

An administrator stores a secret without a token: `provider: token_exchange` and the downstream
`audience` (and `scope`), for an `http` (`bearer_token`) or `quack` (`token`) secret:

```json
{"type": "quack", "provider": "token_exchange", "scope": ["quack:corp.duck"], "params": {"audience": "acl-node"}}
```

On every read, the service mints a token **for the caller** at the identity provider (RFC 8693, as
its own client), and serves it as a dynamic secret:
- **a caller reading directly** gets a token exchanged from the one it called with;
- **under a delegation grant**, the grant's **user** gets a token, never the server. At the grant's
  exchange the service exchanges the user's token for each audience the server may use, with a
  refresh token kept with the grant in memory, and renews from it while the user's IdP session
  lives.

- **Failures:** a lasting refusal is `403 mint_refused`, an outage `503`.
- **An outage at the grant's exchange** does not spoil the session. The grant keeps the user's
  token for this service until that token expires (minutes), and mints from it later, as it does
  for a secret granted to the server after the session opened.
- **A minted token is checked:** its `aud` must name the audience asked for, and never this service
  itself. At PUT, an `audience` equal to this service's own is refused.
- **Refresh tokens are dropped, not revoked at the IdP** (RFC 7009), when a grant ends. They stay
  valid at the IdP until the user's SSO session ends, and renewing keeps that session from going
  idle.

The issuer names the service's client, whose secret comes from the environment:

```yaml
issuers:
  - issuer: https://idp.example/realms/corp
    exchange: {client_id: duckdb-secrets, client_secret_env: TRESOR_EXCHANGE_SECRET}
```

Keycloak (standard token exchange):
- **the service's client:** `standard.token.exchange.enabled`,
  `standard.token.exchange.enableRefreshRequestedTokenType: SAME_SESSION`, and an audience mapper
  per downstream audience;
- **the node's client:** the same refresh attribute, because tresor's exchange asks for a refresh
  token so that Keycloak binds the token to the user's session. The test realm has both.

### Upgrading from before tresor specs/009

- **`policy.create` is gone.** A config that still has it is refused with that message; list the
  principals who may create in `policy.admins`.
- **Old grants are ignored.** A stored grant to a `subject:` or a `client:`, or of any verb but `use`,
  gives nothing now, and the server logs each at start. Re-grant `use` to a role or a group. A
  service account (a node) is granted through a role of its token.
- **Delegation rules are dropped** when a stored file is loaded.
- **An actor's `verbs` changed meaning.** `use` is now the server's own grants, used for its users.
  Any other verb lets **admins** manage through the server. Keep them to what you mean to allow; the
  test configuration lists every verb for its node, which is not a production default.
- **Admin status is taken at the grant's exchange.** A demoted admin keeps managing through a node
  until the grant expires (8 h at most) or is revoked (`DELETE /v1/delegations?subject=…`).

## Identity provider setup (Keycloak)

`server/testdata/keycloak/realm-tresor.json` is the realm the tests import. What matters for a real
deployment:

- A **public client for people** with the standard flow, PKCE `S256` and the redirect URI
  `http://127.0.0.1/*`. Keycloak accepts any port on a loopback redirect, as RFC 8252 requires.
  Enable the device grant if people log in over SSH.
- An **audience mapper** that puts the service's `audience` into access tokens, on the people's
  client and on every service client.
- **Service clients** with service accounts. A client created in the admin console gets the
  `service_account` scope, which adds the `client_id` claim. The imported test realm adds the same
  mapper by hand.

## Conformance

tresor's repository carries the conformance suite: sqllogictests in `test/sql/conformance/`, driven
against a service URL by environment variables. Build tresor, then:

```bash
TRESOR_CONFORMANCE_HOST=secrets.corp.example \
TRESOR_CONFORMANCE_INSECURE=false \
TRESOR_CONFORMANCE_ISSUER=https://login.corp.example/realms/main \
TRESOR_CONFORMANCE_CLIENT_ID=conformance TRESOR_CONFORMANCE_CLIENT_SECRET=… \
build/release/test/unittest --skip-error-messages '' 'test/sql/conformance/*'
```

Set `TRESOR_CONFORMANCE_PERSON=1` and a `BROWSER` that can complete your identity provider's login
to include the person flow. To include the secrets case, seed a secret the conformance client may
use and name it: `TRESOR_CONFORMANCE_SECRET`, `_SECRET_TYPE`, `_SECRET_PATH` (covered by its scope),
`_SECRET_KEY` and `_SECRET_VALUE` (a VARCHAR parameter). `scripts/ci/test_keycloak.sh` runs the whole suite against the reference
server and Keycloak in docker.

## Entra ID, checked live (tresor specs/013)

`scripts/dev/entra_live.sh` runs tresor against an Entra tenant through this server. It takes
everything from the environment and never writes a credential to the repository. It expects three
app registrations:

| App | What | Settings |
| --- | --- | --- |
| the service's API | the audience | an Application ID URI (`api://duckdb-secrets`); a delegated scope `access_as_user`; an app role (e.g. `nodes`); `accessTokenAcceptedVersion: 2` in the manifest; the optional access-token claim `idtyp` (how the server tells an app's token from a person's) |
| people's client | a public client | "Allow public client flows"; a mobile/desktop redirect `http://127.0.0.1/callback` (Entra ignores a loopback port, not the path); the API permission `access_as_user` |
| the node | a confidential client | a certificate (upload the `.crt`); optionally a client secret; the API's app role granted, with admin consent |

```sh
export ENTRA_TENANT=<tenant id> ENTRA_API_CLIENT_ID=<the API app's client id> ENTRA_API_URI=api://duckdb-secrets \
       ENTRA_PEOPLE_CLIENT_ID=<people's client id> ENTRA_NODE_CLIENT_ID=<node client id> \
       ENTRA_NODE_KEY_FILE=node.key ENTRA_NODE_CERT_FILE=node.crt   # ENTRA_NODE_SECRET optional
scripts/dev/entra_live.sh
```

A v2 token's `aud` is the API app's client id, so that is the server's `audience` (and a managed
identity's `AUDIENCE`); the URI builds the scopes.
It prints, per step, the login flow, the subject and the roles, and the server's request lines. It never
prints a token.
