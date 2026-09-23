# Spec 009: permissions, simply — admins manage, roles use, a grant acts with the server's own rights

- **Status**: implemented
- **Date**: 2026-09-23
- **Author**: VGSML (with Claude)
- **Supersedes**: spec 007's delegation rules (the SQL, the protocol's *Rules*, the reference server's
  rules) and spec 007/008's "under a grant, the user's permissions"; spec 005's user writes and grants
  become an administrator's.

## Summary

A simpler permission model, chosen after a design discussion (2026-09-23):
1. **Only administrators manage secrets.** They create, change and delete secrets, and grant their
   use. Users do not create secrets in the service; a user keeps their own locally
   (`CREATE SECRET` in their own DuckDB).
2. **Use is granted to roles and groups only** (`role:`, `group:` from the token). It is never
   granted to one user, and never implied by an administrative role: an administrator uses a secret
   only if one of their roles holds `use`.
3. **A server has a role like anyone else.** A duckdb-acl node's service account (`client:acl-node`,
   or its roles) is granted `use` on what it serves: its ducklake, iceberg, databases. It needs no
   administrative rights.
4. **A delegation grant only proves "this request is for user X's session".** Under a grant:
   - `use` is **the server's own**: the user gets nothing beyond what was granted to the server;
   - **management passes through only for an administrator.** The user's own role must be
     administrative, and the service's policy must let this server pass the verb on. That is how an
     administrator manages tresor through a duckdb-acl node;
   - a token-exchange secret (spec 010) is minted for the grant's user.

   There are no delegation rules.

With this model, planting or redirecting a secret needs an administrator, who is trusted by
definition. A node looks up exactly what its role was granted.

## Problem

Specs 005 and 007 let any user create secrets, grant them to any principal, and write delegation
rules. That opened secret planting: a user's secret on another's paths, granted to a role or
delegated to a server. It also forced one design after another to keep a node's own paths safe
(the closed PR #10). Nobody needed users to share secrets through the service: a user's own
credentials belong in their own DuckDB.

## Design

### Protocol (normative changes to `website/docs/protocol.md`)

- **Administrators** (the service's configuration names them) create, update, delete and annotate
  secrets, and manage grants. Every other caller gets `403 no_verb` for those.
  `whoami.permissions.create` is `true` for administrators and `false` otherwise.
- **Grants** (`PUT /v1/secrets/{name}/grants/{id}`) name a `role:` or a `group:` principal, with
  `use` as the only verb. Any other principal or verb gets `422 invalid_secret`.
- **`use`** comes only from a grant to one of the caller's roles or groups. Neither an
  administrative role nor having created a secret implies it.
- **Delegation.**
  - **Removed:** the *Rules* (`/v1/secrets/{name}/delegations`), the `delegate` verb, rule `mode`s
    and `not_delegable`.
  - **Kept:** grants (`POST /v1/delegations`, the `Delegation` header, revocation) and the actor
    policy, which lists which servers may act for users.
  - **Under a grant:**
    - `use` and the listing are **the actor's own**;
    - a management verb (and `create`) passes only for a user who is an administrator, and only if
      the actor policy lists it. Anything else is `403 actor_not_allowed`;
    - `whoami` answers the user's subject with `actor` set;
    - a token-exchange secret is minted for the grant's user (spec 010).
- **Descriptor.** `permissions` is `["use"]` or `[]` for a user, and all the management verbs for an
  administrator. `delegation` is gone.

### Reference server

- **Config:**
  - `policy.admins` manage;
  - `policy.create` is removed, since only admins create;
  - `policy.actors` keeps its principals. `verbs` are `use` plus the management verbs and `create`
    the server may pass on for administrators.
- **Store.** A secret's `Rules` are gone. A stored file that still has them loads, and the rules are
  dropped.
- **Checks.**
  - `userVerbs` is `use` from a role or group grant, plus the management verbs for an
    administrator.
  - Under a grant, `use` is computed from the **actor's** principals, if the actor policy lists
    `use`. The management verbs apply when the user is an administrator and the actor policy lists
    them.

### tresor

- **Removed:** `corp.delegations`, `corp.add_delegation`, `corp.remove_delegation`.
- **`corp.grant_secret(name, principal, verbs)`** checks the principal (`role:` or `group:`) and the
  verbs (`['use']`) before any request. The service refuses non-administrators.
- **Unchanged:**
  - writes (`CREATE PERSISTENT SECRET … IN corp`), which work for an administrator;
  - spec 008's actor: under a session every call carries the grant, with no fallback to the node's
    own identity. Under the new semantics that is **the node's secrets for the user's statement**,
    so a node's ducklake works under a session.
- **Administering tresor through an acl node** (option b of the discussion). An administrator
  connected to the node through an acl door manages secrets over the session's grant:
  `CREATE PERSISTENT SECRET … IN corp`, `corp.grant_secret(…)`. The node's attachment itself has no
  administrative rights; the service's policy lets the node pass management on, for administrators
  only.
- **duckdb-acl's side** (acl's work, not tresor's; a task for that repository):
  - **Syntax.** `ACL GRANT SECRET <name> TO <role|group> [FROM <catalog>]`, `ACL REVOKE SECRET …`,
    and `CREATE SECRET … ` without `IN`, with the rewriter supplying `IN <catalog>`.
  - **Choosing the catalog.** `FROM`/`IN` if given. Otherwise the attached catalogs of type `tresor`
    (`duckdb_databases()`): exactly one is taken, several or none is an error that says so.
  - **Without tresor.** If tresor is not installed and loaded, the node works as ever: secrets are
    just not created or managed through acl, and the statements say so.

## Enforcement & security

- **No planting.** Only an administrator can put a secret where others' lookups find it, or grant
  its use.
- **No escalation through a node.** Under a grant, a user gets exactly the node's grants: what an
  administrator decided the node serves to its users. acl's gate decides which of the node's
  catalogs and paths a user reaches. A statement under a session never runs with the node's bare
  identity (spec 008): a token-exchange secret is minted for the user, never for the node.
- **Administration through a server is an administrator's.** A node cannot manage by itself. Under
  a grant, management passes only for a user who is an administrator, and only the verbs the node's
  policy lists.

## Testing

- **Go:**
  - admins manage and others get `403`;
  - grants take roles and groups with `use` only;
  - an admin without a role grant has no `use`;
  - under a grant, the actor's secrets are listed and served;
  - management under a grant is refused, except for an administrator through a server whose policy
    allows it.
- **tresor (fake):**
  - the delegation SQL is removed;
  - `grant_secret` refuses other principals and verbs;
  - `actor.test` has the node's secrets under a session through the grant.
- **Conformance and Keycloak:**
  - `etl` is an administrator;
  - the node's role (`nodes`) is granted the node's secret, served under alice's session;
  - alice (no administrator) cannot create through the node;
  - bob (an administrator) creates, grants and drops through the node;
  - rules tests are removed.

## Follow-ups

- spec 010: the `token_exchange` provider, a token for the effective caller: a user directly; the
  node itself; the grant's user under a grant, with a refresh token.
- duckdb-acl: the `ACL GRANT SECRET` / `CREATE SECRET` syntax and the catalog choice above.
