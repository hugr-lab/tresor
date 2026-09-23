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
| `GET` | `/v1/secrets/{name}` | one secret **with material** — requires `use` (or a delegation rule) |
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
  "owner": "role:sales_admins",
  "created_at": "2026-09-01T10:00:00Z",
  "updated_at": "2026-09-10T08:30:00Z",
  "version": "7",
  "dynamic": false,
  "permissions": ["use", "annotate"],
  "delegation": null
}
```

A client lists descriptors (cheap, no material) and fetches material only for the secret its lookup
picks. tresor caches the list for 30 s and material for a few minutes (a dynamic secret until
shortly before `expires_at`, a static one until its `version` changes).

`permissions` lists the verbs **the caller** holds on this secret. `delegation` summarises the
secret's delegation rules, when the caller may see them.

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

The verbs a service decides:

| Verb | Level | Meaning |
| --- | --- | --- |
| `create` | service | create new secrets (in `whoami`, optionally by name pattern) |
| `use` | secret | receive the material |
| `update` | secret | replace params / material |
| `delete` | secret | delete |
| `annotate` | secret | set the comment |
| `grant` | secret | give and take verbs from principals |
| `delegate` | secret | manage delegation rules |

### Grants

| Method | Path | Meaning |
| --- | --- | --- |
| `GET` | `/v1/secrets/{name}/grants` | `[{id, principal, verbs[]}]` — requires `grant` |
| `PUT` | `/v1/secrets/{name}/grants/{id}` | create or replace a grant `{principal, verbs[]}` → `200` with the secret's grants |
| `DELETE` | `/v1/secrets/{name}/grants/{id}` | revoke → `204`, or `404` |

A grant passes on at most the verbs its grantor holds: holding `grant` alone does not let a caller
give itself `use`. The id is the client's choice. A malformed grant (an unknown verb, a principal
without a known prefix) is `422 invalid_secret`. A verb the grantor lacks is `403 no_verb`.

## Delegation

Optional (`capabilities.delegation`). A secret with no rules is **not delegated**.

### Rules

| Method | Path | Meaning |
| --- | --- | --- |
| `GET` | `/v1/secrets/{name}/delegations` | the secret's rules — requires `delegate` |
| `POST` | `/v1/secrets/{name}/delegations` | add a rule |
| `DELETE` | `/v1/secrets/{name}/delegations/{id}` | remove a rule |

```json
{
  "id": "d1",
  "actors": ["client:acl-node-prod"],
  "subjects": ["role:analysts"],
  "mode": "shared",
  "operations": ["read"],
  "scope": ["s3://lake/team-a/"],
  "ttl": 3600
}
```

- `mode: "user"` — the service issues a credential of the user's own; the resource sees the person.
- `mode: "shared"` — the actor receives the shared secret, only to act for that user; the user needs
  no `use` verb.
- `operations` / `scope` narrow the credential the service issues; enforcement is the credential's.

### Acting for a user

A server obtains a **delegation grant** when a user's session opens on it:

`POST /v1/delegations` — authenticated as the server, with the user's access token in the body:

```json
{"subject_token": "<user's access token>", "ttl": 28800}
```

→ `{"id": "…", "subject": "…", "actor": "client:acl-node-prod", "expires_at": "…"}`

From then on the server calls any resource with its own token **and** `Delegation: <id>`. The
service evaluates the **user's** permissions, requires that the actor may act for users for the verb
at hand (for material: a matching delegation rule), and audits both. A grant is bound to its actor;
it is a bearer credential and is revocable centrally.

## Errors

| `type` | Status | Meaning |
| --- | --- | --- |
| `unauthenticated` | 401 | token missing, invalid or expired — refresh and retry once |
| `no_verb` | 403 | the caller's roles do not hold the verb |
| `actor_not_allowed` | 403 | the server may not act for users for this verb |
| `not_delegable` | 403 | no delegation rule matches |
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
