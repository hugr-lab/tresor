# Spec 009: a node looks up only its own secrets — personal ones minted for the session's user

- **Status**: implemented
- **Date**: 2026-09-23
- **Author**: VGSML (with Claude)
- **Supersedes**: in part, spec 008's "a statement under a session gets its user's secrets or none"

## Summary

On a duckdb-acl node a user's statement needs two kinds of credentials:
- **the node's own,** for what the node serves: its ducklake (the object store and the metadata
  database), its iceberg catalogs, its attached databases;
- **the user's own token,** for what the user reaches as themselves: an http API, another acl node
  through quack.

Spec 008 served only the user's secrets under a session. A ducklake catalog of the node then failed
for every user, or needed a grant on its bucket, which would hand users the raw files.

With this spec, **a node looks up only the secrets it owns.** These are what its admin created
through it (ACL NATIVE), and nothing a user creates or grants to the node. A **personal** secret
among them (`personal: true`) is not the node's to use. Under a session it is minted for the
session's user, through the session's grant. **The node never gets a user's secrets.**

## Where it applies

- **An attachment acting for acl sessions** (`ACT_FOR_SESSIONS`, a service login) is a node. Its
  lookups consider only the secrets its login owns, both under a session and in its own work.
- **Any other service login, under an acl session,** serves its own secrets the same way, without
  personal ones.
- **A person's attachment under an acl session** serves nothing.
- **Outside an acl session** the ordinary rule holds for everyone but a node: a person's attachment
  serves that person's secrets, personal ones minted for them; a service's serves its own.

## Design

### What the node looks up

- **Ownership.** At ATTACH, tresor learns its login's principal from `whoami`:
  `subject:<issuer>|<subject>`, the protocol's ownership principal. A node's lookups
  (`LookupSecret`, `GetSecretByName`, `duckdb_secrets()`, httpfs's refresh through the tresor
  provider) consider only descriptors whose `owner` is that principal. A service whose whoami names
  no issuer and subject cannot host a node: the ATTACH is refused.
- **What owning excludes:**
  - a user's secret granted to the node (`use` on `client:acl-node`);
  - every secret an admin role reaches;
  - a user's secret delegated to the node by a rule.

  None of them enters the node's lookups, so users cannot plant or redirect the node's paths. The
  node's grants and admin role remain for management: in ACL NATIVE, its admin creates secrets,
  grants them, and lists what is registered.
- **Candidates.** Candidates are tried best-scoped first; on a tie, a personal one comes first.
  - A secret of the node's whose material the service refuses is skipped for the next, and
    remembered by name and version.
  - A **personal** candidate that cannot be had **ends the search**: no usable grant, or the user
    refused. Its path is the user's, and a user's statement must never fall through to the node's
    own credential for it.

### Personal secrets

- **Protocol.** A descriptor gains `personal: true` (`website/docs/protocol.md`, normative): the
  material is minted per user. A service gives it only to a user's own login, or to an actor under a
  delegation grant, minted for the grant's user.
- **In a node's lookup:**
  - **under a session:** its material is fetched with the session's grant (waited for up to
    `SESSION_GRANT_WAIT`, and only here) and cached in the session's own view, never the node's.
    With no usable grant, it is not served;
  - **outside a session** it has no user, and is not served.
- **Minting** these secrets in the reference server is spec 010. The protocol requires a personal
  secret to be dynamic, says to whom it is given, and forbids a client to fall back to another
  credential for its path.
- **Diagnosis.** `corp.whoami()` gains a `principal` column: what the login owns things as. A node
  whose secrets are not owned by exactly that principal has none. Compare it with the `owner`
  column of `corp.secrets()`.

### Explicit calls

`corp.whoami()`, `corp.secrets()`, writes and the management functions under a session are the
user's, through the grant, or refused: unchanged. A user does not reach the node's management
rights through it.

**Across attachments.** Two attachments whose lookups cover one path are decided by DuckDB's own rule
(the longest scope, then the storages' tie-break: the first registered wins). Keep one attachment per
service on a node.

## Enforcement & security

- **The node's paths cannot be redirected by users.** Suppose delegated or granted secrets were
  looked up. A user could put a secret on the node's lake bucket, with an `ENDPOINT` of theirs, and
  have it delegated or granted to the node. The node's ducklake writes would then land on the
  user's endpoint while its metadata committed them to the shared catalog. Only what the node owns
  is looked up.
- **The node's secrets are guarded by acl's gate, not the credentials.** A user who could name the
  node's paths directly would use the node's secrets for them: `read_parquet`, `COPY`, `ATTACH`, a
  replacement scan, any extension's URL-fetching function. acl's `readers` category is nobody's by
  default, and a function in no category is refused.
- **A user's token only through the grant,** and only for personal secrets the node owns. It goes
  where the secret's owner, the node's admin, said.
- **A contract mismatch** (acl built from another `acl_connection` version) is served like a session
  without a grant: the node's own non-personal secrets, and explicit calls refused.
- **The node's paths do not wait** for a new session's grant. Only personal secrets do.
- **Ownership is not integrity.** Whoever holds `update` on a node's secret can change it in place.
  Grant `update` and `grant` on the node's secrets to its admins only (spec 011 takes this further).
- **Unsessioned connections are the node's work.** That includes writes: a secret created on one is
  the node's. Keep user-influenced SQL off them.

## Testing

`test/sql/attach/actor.test`. In the fake's `acting` realm the node owns `node_lake`, `infra_lake`,
`shared_lake` and the personal `user_lake`; mallory's `planted_lake` (longer-scoped on the node's
path) is granted to it.
- **Outside a session:**
  - the node's own are served;
  - `planted_lake` is not;
  - the personal secret is not.
- **Under a session:**
  - the node's own paths are served;
  - `planted_lake` never is;
  - alice's own and delegated secrets are not;
  - `user_lake` is minted for her (`USER-alice`);
  - `duckdb_secrets()` shows only these.
- **A person's attachment** serves nothing.
- **With no usable grant:** the node's own, no personal secret.
- **Explicit calls:** unchanged.

**Keycloak** (`reference_server/actor.test`): the node creates `node_lake` in its own work, and under
alice's session its lookup serves it. The owner's secret delegated to the node is not looked up,
though alice's `node.secrets()` lists it. **Real duckdb-acl** (`test/acl/actor.sql`): the same
through acl's virtual functions.

## The review's findings (applied)

Two designs came before this one: the delegated secret first, then the node's secret first. An
independent review and the discussion that followed found:
- **Delegated first let a user redirect the node's paths.**
- **Node first still let users plant.** A secret a user granted to the node, or any secret the
  node's admin role reached, joined the node's lookups.
- **A person's attachment served that person's secrets to every session.**

Hence: a node looks up only what it owns, personal secrets are minted through the grant, and a
person's attachment serves nothing under a session. A second review found:
- **A personal secret that could not be had** fell through to the node's own secret on the same
  path, giving a user's statement the node's credential. A personal candidate now ends the search,
  and wins ties.
- **The "remembered" refusals** were written to a view that was never read; now they are read.
- **The protocol's `personal` text and the owner format** are now precise.
- **The security page** again says unsessioned connections are the node's work, writes included,
  and that ownership is not integrity.

Smaller fixes:
- a refused candidate is skipped and remembered;
- the refresh follows the lookup;
- the node's paths do not wait for a grant;
- the docs are corrected.

## Follow-ups

- **spec 010:** minting personal secrets in the reference server. A user's own login gets a token
  exchanged on demand; a grant gets one exchanged at the grant with a refresh token, renewed from
  it.
- **spec 011:** secret planting for everyone. A service policy on who may grant `use` to whom (a
  recommendation in the protocol, implemented in the reference server), and tresor looking up
  only secrets of trusted owners.
