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
- **Use without seeing**, through a server: an administrator grants a secret to a server's role, and
  the server uses it for its users' statements while they never receive it. The production password
  stays on the server, and every use is audited under the user's name.
- **Only administrators manage.** Users do not create or share secrets in the service, so nobody
  but an administrator can put a secret where others' lookups find it (no planting).

## What a server must never do

A server acting for users **never adds its own authority** to a user's request beyond what an
administrator granted it. Every call it makes on a user's behalf carries the user's delegation
grant. The service answers with the server's own grants for the user's statement, and passes
management through only for a user who is an administrator, where its policy allows. On a duckdb-acl
node, tresor holds to this per statement. A statement that acl publishes as running under a user's
session is served through that session's grant, or gets nothing from the service. It never falls
back to the node's bare identity, whether the grant is pending, failed or revoked, or the attachment
does not act for sessions at all. The session is what acl publishes on the statement's connection. A
lookup made without a connection (a background refresh), or on an internal connection some extension
opens, runs as the node. Keep such work out of users' reach with acl's function gate.

The node's secrets are kept from users by **acl's function gate, not by the credentials**. A user
who could name the node's paths directly (`read_parquet`, `COPY`, `ATTACH`, a replacement scan, any
extension's URL-fetching function) would read them with the node's grants. Keep acl's `readers`
category closed to users; it is closed by default.

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
- **A person's refresh token is kept in the OS credential store** (specs/012), and only that: never
  a file, never an access token, never a service's credential. It goes to its identity provider only,
  both for a refresh and for a revocation.
  - The store protects it from other OS users and from a copied disk. It does not protect it from
    another process of the same user.
  - On macOS the item belongs to the program that stored it (`duckdb`, `python3`). Any script that
    program runs reads it without asking; another program has to ask first.
  - A login is kept per service (issuer, client, service). Two services behind one identity provider
    and public client could ask for each other's scope, so tresor never refreshes one service's login
    for another: a new service always gets a login of its own.
  - On Linux the Secret Service provider decides where the collection lives. KeePassXC may keep it
    in a synced file.
  - On macOS the login keychain file travels with a backup.
  - If this is too much for you, use `REMEMBER false`, `tresor_keychain = 'off'` or
    `TRESOR_KEYCHAIN=off`.
