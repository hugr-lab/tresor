---
sidebar_position: 4
title: Protocol — duckdb-secrets/1
---

# The `duckdb-secrets/1` protocol

:::caution Draft
This is the draft of version 1. It becomes normative with tresor's first release; until then it
may change without a version bump.
:::

A **secrets service** is any HTTPS server that implements this page. How it stores secrets, how it
models policy and how it maps identity-provider claims to roles are its own business — the protocol
fixes only what a client sees.

## Conventions

- Transport: HTTPS, JSON bodies (`application/json`). A client may speak plain http to a service
  on the **loopback** interface when its user explicitly asks for it (development, tests), and never
  otherwise.
- Authentication: `Authorization: Bearer <access token>`, issued by an OIDC provider the service
  declares in its discovery document. The service verifies the token itself — signature against the
  issuer's JWKS, `iss`, **`aud`** (the token must be issued *for this service*), expiry.
- Errors: RFC 9457 `application/problem+json`, with a `type` from the list in [Errors](#errors).
- A **principal** is a string with a conventional prefix: `role:<name>`, `group:<name>`,
  `subject:<issuer>|<sub>`, `client:<client_id>` (a service, or a server acting as an actor). How
  claims map to principals is the service's business. Only `subject:` identifies a caller. The other
  prefixes name something a caller holds: a `client:` name is shared by every token of that client,
  and, across issuers, by same-named clients. Ownership and identity are therefore always
  `subject:`.
- Names of secrets are compared exactly. A client sends them in one canonical form (tresor: lower
  case, as DuckDB compares secret names case-insensitively).
- Bodies: a client sends only the fields listed here. A service may refuse unknown fields with
  `422 invalid_secret`.
- Every error is a problem document, including an unknown route or method (`404 not_found`).

## Discovery

`GET {base}/.well-known/duckdb-secrets` — **no authentication**.

```json
{
  "protocol": "duckdb-secrets/1",
  "api": "https://secrets.corp.example",
  "issuers": [
    {
      "issuer": "https://idp.corp.example/realms/main",
      "client_id": "duckdb",
      "scopes": ["openid", "offline_access"],
      "audience": "duckdb-secrets",
      "human_flows": ["authorization_code", "device_code"],
      "service_flows": ["client_credentials", "private_key_jwt", "token_exchange", "federated"]
    }
  ],
  "capabilities": {"write": true, "annotate": true, "dynamic": true, "delegation": false}
}
```

- `api` — the absolute base URL the resource paths below are appended to (they carry the version:
  `{api}/v1/whoami`). It is at least as secure as the discovery request (https, unless both are
  loopback http).
- `issuers` — every identity provider the service accepts. A client continues with the issuer's own
  `/.well-known/openid-configuration` (RFC 8414: the document's `issuer` must match). With several
  issuers, the **user names one**. A client does not pick one by list order, since that would choose
  an identity for them.
- `human_flows` / `service_flows` — the login flows the service expects clients to use with this
  issuer. When present, a client attempts no others.
- `scopes` — what a person's login requests. A service's client-credentials login requests them
  without `openid` and `offline_access`, unless it is configured with its own.
- `audience` — the `aud` the service requires. Making the issuer put it into tokens requested with
  `scopes` is identity-provider configuration (a client scope, an application ID URI). Clients do not
  send it.
- `client_id` — a **public** client for people (authorization code with PKCE, loopback redirect).
- `capabilities.delegation` — whether the optional [delegation](#delegation) resources exist.
  Grants are not optional in version 1.

## Identity

`GET /v1/whoami` →

```json
{
  "issuer": "https://idp.corp.example/realms/main",
  "subject": "7f9c…",
  "roles": ["role:analysts", "group:sales"],
  "actor": null,
  "expires_at": "2026-09-18T17:00:00Z",
  "permissions": {"create": ["team_a_*"]}
}
```

`actor` is set when the call is made by a server on a user's behalf ([delegation](#delegation)).
`roles` lists the caller's principals other than its `subject:` (`role:`, `group:`, and `client:`
for a service). `permissions.create` is `true`, `false`, or a list of name patterns the caller may
create.

## Secrets

| Method | Path | Meaning |
| --- | --- | --- |
| `GET` | `/v1/secrets[?type=<type>]` | descriptors the caller may see — **without material** |
| `GET` | `/v1/secrets/{name}` | one secret **with material** — requires `use` |
| `PUT` | `/v1/secrets/{name}` | create or replace (see [Conditional writes](#conditional-writes)) |
| `DELETE` | `/v1/secrets/{name}` | delete — requires `delete` |
| `PATCH` | `/v1/secrets/{name}` | `{"comment": "…"}` — requires `annotate` |

### Descriptor

```json
{
  "name": "crm_ro",
  "type": "mssql",
  "provider": "config",
  "scope": ["mssql://crm.corp.example"],
  "comment": "Read-only access to the CRM database",
  "owner": "subject:https://idp.example/realms/corp|8f1c2d3e-…",
  "created_at": "2026-09-01T10:00:00Z",
  "updated_at": "2026-09-10T08:30:00Z",
  "version": "7",
  "dynamic": false,
  "permissions": ["use"]
}
```

A client lists descriptors (no material) and fetches material only for the secret its lookup
picks. It may cache material; a dynamic secret's no longer than its `expires_at`.

`permissions` lists the verbs **the caller** holds on this secret, and is always a list (possibly
empty): `["use"]` for a user whose roles are granted it, the management verbs for an administrator.

### Material

`GET /v1/secrets/{name}` adds:

```json
{
  "params": {
    "host": "crm.corp.example",
    "user": "crm_reader",
    "password": {"type": "VARCHAR", "value": "…"},
    "port": {"type": "INTEGER", "value": 1433},
    "extra_http_headers": {"type": "MAP(VARCHAR, VARCHAR)", "value": {"X-Tenant": "sales"}}
  },
  "redact_keys": ["password"],
  "expires_at": null
}
```

Parameters are typed so a secret round-trips into DuckDB without loss: `{"type": "<DuckDB logical
type>", "value": <JSON>}`; a bare string is shorthand for `VARCHAR`. Nested values (`MAP`, `STRUCT`,
`LIST`) are JSON objects and arrays. Version 1 covers key-value secrets — every mainstream type
(`s3`, `gcs`, `r2`, `azure`, `http`, `postgres`, `mysql`, `mssql`, …).

### Dynamic secrets

`"dynamic": true` means the service generates `params` on every `GET` and returns an `expires_at`.
A client caches the material until shortly before that time.

A dynamic secret's material may depend on **the caller**, for example a token minted for them for a
downstream server:
- Under a delegation grant, such material is the **grant's user's**, never the server's own.
- A client MUST NOT serve material fetched for one caller to another: not across users, and not
  between a server's own work and a user's session.
- A service that cannot produce it answers `403 mint_refused` for a lasting refusal (the user's
  session at the identity provider has ended; the IdP refused), and `503 service_unavailable` for
  an outage. A client MUST fail the lookup that needs it with the service's detail, and MUST NOT go
  on without it.

### Conditional writes

`PUT` carries the secret as `{type, provider, scope, params, redact_keys}` (and optionally
`comment`) and follows HTTP preconditions, which is exactly what DuckDB's statements need:

| SQL | Request | On `412 Precondition Failed` |
| --- | --- | --- |
| `CREATE PERSISTENT SECRET … IN corp` | `PUT` + `If-None-Match: *` | error: already exists |
| `CREATE PERSISTENT SECRET IF NOT EXISTS …` | `PUT` + `If-None-Match: *` | silently nothing |
| `CREATE OR REPLACE PERSISTENT SECRET …` | `PUT` (no precondition): replaces a secret the caller holds `update` on, or creates one under its `create` | — |
| a replace that must not lose a concurrent change | `PUT` + `If-Match: "<version>"` (the `ETag` of the read) | error: changed meanwhile |
| `DROP PERSISTENT SECRET … FROM corp` | `DELETE`; `IF EXISTS` ignores `404` | — |

- **Answers.** `PUT` answers `201` when it created and `200` when it replaced, with the descriptor
  and its `ETag` (the quoted `version`). `DELETE` answers `204`. `PATCH` answers `200` with the
  descriptor. `If-None-Match` with an ETag (not `*`) fails only on that version.
- **A name the caller cannot see.** A `PUT` to a name that exists but is invisible to the caller is
  `403 no_verb`, not `412`. A caller allowed to create therefore learns that the name is taken, but
  nothing else about the secret. Every read of an invisible secret is `404`, like a missing one.

## Permissions

**Administrators** manage secrets; everyone else only uses what their roles are granted. Which
principals are administrators is the service's configuration.

| Verb | Level | Held by |
| --- | --- | --- |
| `create` | service | administrators (in `whoami`: `permissions.create` is `true` or `false`) |
| `use` | secret | the principals a grant names: roles and groups |
| `update` | secret | administrators: replace params / material |
| `delete` | secret | administrators |
| `annotate` | secret | administrators: set the comment |
| `grant` | secret | administrators: give and take `use` |

- **`use` comes only from a grant.** A grant gives `use` to a `role:` or a `group:` principal. An
  administrative role does not imply `use`: an administrator uses a secret only when one of their
  roles is granted it, as anyone else. Creating a secret does not imply it either.
- **Users do not create or share secrets.** A user keeps their own credentials in their own client
  (tresor: DuckDB's `CREATE SECRET`). So only an administrator can put a secret where others'
  lookups find it, or let anyone use it: a user cannot plant a secret on another's paths.
- Every other caller gets `403 no_verb` for the management verbs.

### Grants

| Method | Path | Meaning |
| --- | --- | --- |
| `GET` | `/v1/secrets/{name}/grants` | `[{id, principal, verbs[]}]` — requires `grant` |
| `PUT` | `/v1/secrets/{name}/grants/{id}` | create or replace a grant `{principal, verbs: ["use"]}` → `200` with the secret's grants |
| `DELETE` | `/v1/secrets/{name}/grants/{id}` | revoke → `204`, or `404` |

Writes are immediate: a client has no transaction to join them to, and tresor documents that a
`ROLLBACK` does not undo them.

A grant names a `role:` or a `group:` principal and the verbs `["use"]`, nothing else. Any other
principal or verb is `422 invalid_secret`. The id is the client's choice.

## Delegation

Optional (`capabilities.delegation`). A **server** that serves users (a duckdb-acl node, a data
platform) acts for them through a **delegation grant**. A grant proves "this request is for user X's
session". It does not add the user's rights to the server's:
- **`use` is the server's own.** The user gets exactly what an administrator granted the server, for
  the statements the server runs for them, and nothing more.
- **Management passes through a server only for an administrator.** The user must hold an
  administrative role themselves, and the service's policy must let this server pass that verb on.
  This is how an administrator manages secrets through a node.
- Material that depends on the caller (the reference server's `token_exchange`) is minted for the
  grant's **user**, never for the server.

### Actors

A service decides which servers may act for users at all (`client:` principals), and which
management verbs each may pass on for administrators. Everything else is `403 actor_not_allowed`:
a server that may not act, or not for the verb at hand.

### Acting for a user

A server obtains a **delegation grant** when a user's session opens on it:

`POST /v1/delegations` — authenticated as the server, with the user's access token for this service
in the body:

```json
{"subject_token": "<user's access token>", "ttl": 28800}
```

→ `201 {"id": "…", "subject": "…", "actor": "client:acl-node-prod", "expires_at": "…"}`

- **The subject token** is a person's access token for this service (not a service's, and never the
  actor's own), verified like any bearer token. The user's principals are taken at the exchange; a
  new exchange picks up changed roles. The user hands the token to the server for exactly this
  exchange. The server forwards it to its audience, the service, and must keep it no longer.
- **Getting the subject token** (non-normative). The token a user presented to the server was issued
  *for the server*: its audience is not this service. The server exchanges it at the identity
  provider that issued it — RFC 8693 token exchange, or Entra's On-Behalf-Of — for a token whose
  audience is this service, and sends only that one here. The tresor client does this for
  duckdb-acl's sessions (`ACT_FOR_SESSIONS`).
- **Lifetime.** A grant may outlive the user's token, because a session outlives an access token.
  The service caps `ttl`. A server asks for the session's remaining lifetime and revokes the grant
  when the session ends (non-normative).
- **Using it.** From then on the server calls with its own token **and** `Delegation: <id>`. The
  service applies the rules above and audits both identities. `whoami` answers the user, with
  `actor` set to the server's `client:` principal, and `permissions.create` is what the user may
  create *through this server*. `GET /v1/secrets` lists what the server may use, plus, for an
  administrator, what they may manage through it.
- **Binding.** A grant is bound to its actor. Presented with another caller's token it is refused
  with `401 unauthenticated`: a stolen grant alone is useless.
- **Revocation:**
  - `DELETE /v1/delegations/{id}`, by its actor or an admin, answers `204`. The id travels in the
    path, so neither a service nor a proxy in front of it should log the path.
  - `DELETE /v1/delegations?actor=client:…&subject=subject:…` is **central revocation**. An admin
    revokes every grant matching the filters (at least one filter is required). Any other caller
    revokes the grants made for themselves, which ends every session a server holds for them. It
    answers `{"revoked": n}`.
  - A grant is a bearer credential: never logged.

## Errors

| `type` | Status | Meaning |
| --- | --- | --- |
| `unauthenticated` | 401 | token missing, invalid or expired — refresh and retry once |
| `no_verb` | 403 | the caller's roles do not hold the verb |
| `actor_not_allowed` | 403 | the server may not act for users for this verb |
| `mint_refused` | 403 | material minted for the caller could not be minted (the detail says why) |
| `not_found` | 404 | no such secret (or not visible) |
| `precondition_failed` | 412 | `If-None-Match` / `If-Match` not met |
| `invalid_secret` | 422 | the secret does not validate |
| `service_unavailable` | 503 | try later |

## Conformance

A service is `duckdb-secrets/1` when it passes the **conformance suite**: sqllogictests in tresor's
repository (`test/sql/conformance/`), driven against the service's URL through environment
variables. It checks what a client can observe; today that is a service login and a person login,
each followed by `whoami`. The suite grows with the client. The
[reference server](./reference-server.md) passes it in CI, next to a real Keycloak.
