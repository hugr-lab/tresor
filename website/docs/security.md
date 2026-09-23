---
sidebar_position: 6
title: Security model
---

# Security model

## What a role can protect — and what it cannot

On a person's machine the DuckDB process is theirs: whatever their role lets the service hand over,
they can read — from memory, or from `duckdb_secrets()` when redaction is not locked. A role on a
**static** secret therefore protects it only from people who lack the role; anyone who holds `use`
effectively holds the secret.

That is why the service, not the client, is where protection lives, and why tresor leans on two
things beyond roles:

- **Dynamic, personal credentials** for people: a tagged STS session, a temporary database user, a
  token issued on the user's behalf. The resource sees the person, the audit trail names them, and
  revoking the person at the identity provider revokes the access.
- **Use without seeing**, through a server: with a `shared` delegation rule a server uses a secret on
  a user's behalf while the user never receives it — the production password stays on the server,
  every use is audited under the user's name.

## What a server must never do

A server acting for users **never adds its own authority** to a user's request. Every call it makes
for a user's resource carries the user's delegation grant; the service checks the user's rights, the
delegation rule, and that this server may act for users at all. On a duckdb-acl node, tresor holds to
this per statement:
- **A node looks up only the secrets it owns** (created through it by its admin). A user's secret
  never enters its lookups, whether the user created it, granted it to the node, or delegated it by
  a rule, and neither does whatever the node's admin role can reach. So no user can plant a secret
  on the node's paths or redirect its lake writes to an endpoint of their own.
- **A personal secret of the node's** is minted for the session's user through the session's grant,
  and never used as the node's own.
- **Explicit calls** (whoami, listings, writes, management) are never the node's under a session.
- **A person's attachment** serves nothing under a session.

**Ownership is not integrity.** The node's secrets are as safe as the set of principals who may
change them. Anyone holding `update` on one (a service admin role, or whoever the node's admin
granted it to) can change its `ENDPOINT` and params in place, and the node will follow. Grant
`update` and `grant` on the node's secrets to nobody but its admins.

**What counts as a session is what acl publishes.** A lookup made without a connection (a
background refresh), or on an internal connection some extension opens, is the node's own work.
So is a **write**: a `CREATE PERSISTENT SECRET … IN corp` on such a connection is owned by the node,
and enters its lookups. Keep user-influenced SQL off unsessioned connections. A service attachment
*without* `ACT_FOR_SESSIONS` follows the ordinary rule outside sessions, and considers every secret
it may use, including ones users granted it. On an acl node, give the node's own work an acting
attachment.

The node's secrets are kept from users by **acl's function gate, not by the credentials**. A user
who could name the lake's bucket directly (`read_parquet`, `COPY`, `ATTACH`, a replacement scan, any
extension's URL-fetching function) would read it with the node's key. Keep acl's `readers` category
closed to users; it is closed by default. Under a session, `duckdb_secrets()` would show the node's
secret names and scopes; acl's gate keeps it from principals. If acl is built from another contract
version, tresor cannot tell whose statement it is: it serves the node's own non-personal secrets
only and refuses explicit calls.

On a server, lock the configuration so users cannot widen what the process reveals:
`allow_unredacted_secrets = false`, `lock_configuration = true`, and no `CREATE SECRET` for
principals (the policy layer's job).

## What the client never does

- write secret material to disk — the storage is persistent **in the service**, not locally;
- log or emit secret material, tokens, session handles or delegation grant ids — audit events carry
  names, verbs and outcomes only;
- send a user's identity-provider token anywhere but to the service it was issued for (`aud`) — a
  session's token acting for a user goes only to the identity provider that issued it, to be
  exchanged. The exchanged token goes to the service only if its `aud` names the audience the node
  pinned. tresor overwrites its copies once the grant arrives. That is best effort: transport
  buffers are not in its hands.

## Logins

- People log in directly with the identity provider — authorization code with PKCE and a loopback
  redirect, or a device code. The secrets service is not a login hub: other servers (a DuckDB node
  behind a gateway, a data platform) need identity-provider tokens too, and one login mints them for
  each audience.
- Services log in with their own credentials — client credentials, a private-key JWT, or a federated
  workload assertion — never with a stored person's token.
