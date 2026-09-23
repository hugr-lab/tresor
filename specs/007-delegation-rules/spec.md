# Spec 007: delegation — rules, grants, and acting for a user (the service side and the rules' SQL)

- **Status**: implemented; rules removed and a grant acts with the server's rights - superseded by [009](../009-permissions-v2/spec.md)
- **Date**: 2026-09-23
- **Author**: VGSML (with Claude)

## Summary

A server (a duckdb-acl node, hugr) that runs a user's queries must use secrets **as that user**. It
must never add its own authority to theirs (spec 001, design §6). The protocol's optional
*Delegation* part is how this works:
1. A secret's owner writes **delegation rules**: which servers may act, for whom, and how.
2. A server exchanges the user's token for a **delegation grant** when the user's session opens.
3. The server then calls the service with its own token and the grant.

This spec makes that part concrete:
- the protocol page fixes the details it left open;
- the **reference server implements it**: rules, grant exchange, the `Delegation` header, and actor
  policy;
- tresor gets the SQL for rules: `corp.delegations`, `corp.add_delegation`, `corp.remove_delegation`.

tresor as the **actor** (using a grant inside an acl node's session) needs acl's per-connection
state (`acl_connection.hpp`, duckdb-acl's contract) and is a later spec.

## Problem

- **Without delegation, a server can only use its own identity.** Either every user of a node gets
  the node's reach (the confused deputy), or delegated reads (`read_json('https://…')`, `COPY TO
  's3://…'`) stay forbidden on servers.
- **The protocol page leaves details open:** rule ids, the grant's lifetime, which verbs an actor
  may exercise, and what `whoami` says under a grant.

## Design

### Protocol (normative changes to `website/docs/protocol.md`)

**Rules** (`/v1/secrets/{name}/delegations`, verb `delegate`):
- `POST` takes `{actors[], subjects[], mode, operations?, scope?, ttl?}` and answers `201` with the
  rule, including its **service-assigned** `id`. `GET` lists the rules; `DELETE …/{id}` answers
  `204` (or `404`).
- `actors` are `client:` principals, and `subjects` any principals. `mode` is `shared` or `user`. A
  service that cannot issue personal credentials refuses `user` with `422 invalid_secret`; the
  reference server refuses it.
- `operations` and `scope` narrow what a `user`-mode credential is issued for. `ttl` bounds the
  delegated material's lifetime (seconds).

**Actor policy** (the service's configuration; the protocol names only its effects):
- An actor must be **allowed to act for users at all**. Otherwise the answer is `403
  actor_not_allowed`.
- It is allowed per verb, and management verbs (`update`, `delete`, `annotate`, `grant`,
  `delegate`) are denied unless configured: a compromised node must not manage secrets for everyone
  who ever connected to it.
- Material through a grant additionally needs a **rule** matching the actor and one of the user's
  principals. Otherwise the answer is `403 not_delegable`, even if the user holds `use`: a secret
  without a rule is not delegated.

**Grants** (`/v1/delegations`):
- **Exchange.** `POST {subject_token, ttl?}`, authenticated as the actor. The `subject_token` is the
  user's access token *for this service*, verified like any bearer token. The answer is `201 {id,
  subject, actor, expires_at}`.
  - The actor must be allowed to act for users (else `403 actor_not_allowed`).
  - The grant **may outlive the user's token**: a session outlives an access token (design §6.4). The
    service caps `ttl` (the reference server: 8 h, default 1 h).
  - The user's principals are **taken at exchange**; a new exchange picks up changed roles.
- **Revoke.** `DELETE /v1/delegations/{id}`, by the actor that holds the grant or an admin. It
  answers `204`.
- **Use.** A request carrying the actor's token **and** `Delegation: <id>`. The grant must be alive
  and **bound to this actor** (the same `subject:`). Otherwise the answer is `401 unauthenticated`,
  with the reason logged: a grant presented by another actor is not a grant.
  - The effective caller is the user, and permissions are the user's.
  - The actor policy is applied per verb. Material needs a rule, as above.
- **`whoami` under a grant** answers the user's `subject` and `roles`, with `actor` set to the
  actor's `client:` principal.
- **Listing under a grant.** `GET /v1/secrets` lists what the user sees, plus secrets whose rules
  delegate to this actor for this user (`permissions: ["use"]`).

### Reference server

- **Config.**

  ```yaml
  policy:
    actors:
      - {principal: client:acl-node, verbs: [use]}
  ```

  An actor must be a service token (the issuer's `service` rule).
- **Store.** Rules are part of the secret's record (and its file). Grants live in memory only:
  bearer credentials are never written to disk, and a restart ends them, as it ends sessions.
- **Checks.** A request with a `Delegation` header goes through the checks above. The request log
  names the actor and the user; the grant id is never logged.
- **Discovery** says `capabilities.delegation: true`.

### tresor (the rules' SQL)

| Call | Request | Returns |
| --- | --- | --- |
| `corp.delegations(name)` | `GET …/delegations` | `id, actors[], subjects[], mode, operations[], scope[], ttl` |
| `corp.add_delegation(name, actors, subjects, mode := 'shared', operations := [], scope := [], ttl := NULL)` | `POST …/delegations` | the rule as stored |
| `corp.remove_delegation(name, id)` | `DELETE …/delegations/{id}` | the removed rule's id |

- The discovery's `capabilities` are kept in the session. The three calls refuse with "does not offer
  delegation" when the capability is off, before any request.
- The service's answers are mapped as in spec 005. A `403 no_verb` means the caller lacks
  `delegate`.

## Enforcement & security

- **A server never adds its own authority.** Under a grant every check uses the *user's*
  principals, the actor policy only takes away, and material needs an explicit rule.
- **Grants are bearer credentials.** They are bound to their actor, capped in time, revocable,
  held in memory, and never logged.
- **A stolen grant alone is useless.** It must come with the actor's own valid token.

## Testing

- **Reference server (Go):**
  - rules CRUD with `delegate`, and `user` mode refused;
  - the exchange (a person's token refused as an actor, an actor not in the policy, a bad subject
    token, the ttl cap);
  - material through a grant: shared rule → 200 without the user's `use`; no rule → `not_delegable`;
    a rule for another actor or another subject → `not_delegable`;
  - a grant presented by another actor → 401;
  - management verbs through a grant → `actor_not_allowed` unless configured;
  - `whoami` with `actor`; listing under a grant; revocation; expiry.
- **tresor:**
  - the fake grows rules (and `capabilities.delegation` per realm);
  - `test/sql/attach/delegations.test` covers add, list, remove, the capability off, and errors;
  - the conformance suite gains `delegations.test`, rules CRUD against the reference server as the
    owner, `etl`.
- **The actor path end to end** (a grant used by tresor inside a server) comes with the actor spec.
  The reference server's Go tests cover it at the HTTP level now.

## The review's findings (applied)

An independent review, the worst of them reproduced:

- **CRITICAL: a rule's `use` could become a standing grant.** Under a grant, the grant check used the
  effective verbs, which include a rule's `use`. A server allowed `grant` could give the user, or
  **itself**, a permanent `use`, and then read the secret with no grant at all. Now a grant passes
  on only the user's own verbs, intersected with the actor policy (`grantable`). A regression test
  pins both directions.
- **`delegate` alone yielded the material** through a rule its author wrote for themselves. Now a
  rule's author must hold `use` too, and the protocol says so.
- **Central revocation was impossible**: revoke was by id only, and ids are never listed. Now
  `DELETE /v1/delegations?actor=…&subject=…` lets admins revoke by filter and users revoke their own
  grants.
- **Actors were matched by an unqualified `client:` name.** A same-named client of another issuer
  counted as the same actor. `policy.actors` now takes an optional `issuer`, and an actor with no
  verbs is refused in the config.
- **A huge `ttl` overflowed into an already-expired grant.** It is now clamped before the
  multiplication.
- **Smaller fixes:**
  - grants are capped at 100 000 and purged at most once a second;
  - a subject token must be a person's, never the actor's own;
  - under a grant, whoami's `create` follows the policy;
  - listings under a grant carry `permissions: []`, never `null`;
  - a rule's `ttl` sets the delegated material's `expires_at`;
  - the descriptor's `delegation` summarises the rules for callers who hold `delegate`;
  - the client's `delegations()` is chunked, and a sub-second or textual `ttl` is handled;
  - the fake is as strict as the server (actors, subjects, rule ids never reused, locking);
  - expiry is tested with the server's clock.

## Alternatives considered

- **Material through a grant on the user's `use` alone, without a rule.** A secret the user may
  `use` on a laptop is not thereby safe for a server to hold for them. The owner decides with a
  rule.
- **Grants persisted with the store.** They are bearer credentials, and keeping them on disk buys
  little: acl sessions do not survive a restart either.
- **Server-chosen actor from the token's `azp` with no policy.** Any service account could then act
  for users. The actor policy is an explicit allow-list.

## Follow-ups

- tresor as the actor: the grant from `acl_connection` (duckdb-acl's contract) used by the storage's
  lookups in that connection.
- `user` mode in the reference server, with a dynamic backend.
