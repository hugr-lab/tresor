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
on a user's behalf carries the user's delegation grant; the service checks the user's rights, the
delegation rule, and that this server may act for users at all. A delegated secret is never resolved
with the server's own identity when the user's is missing — that would make every user a confused
deputy of the server. On a duckdb-acl node, tresor holds to this per statement. A statement that
runs under a user's session is served through that session's grant, or gets nothing from the
service. It never falls back to the node's own identity, whether the grant is pending, failed or
revoked, or the attachment does not act for sessions at all.

On a server, lock the configuration so users cannot widen what the process reveals:
`allow_unredacted_secrets = false`, `lock_configuration = true`, and no `CREATE SECRET` for
principals (the policy layer's job).

## What the client never does

- write secret material to disk — the storage is persistent **in the service**, not locally;
- log or emit secret material, tokens, session handles or delegation grant ids — audit events carry
  names, verbs and outcomes only;
- send a user's identity-provider token anywhere but to the service it was issued for (`aud`) — a
  session's token acting for a user goes only to the identity provider that issued it, to be
  exchanged, and is wiped as soon as the grant arrives.

## Logins

- People log in directly with the identity provider — authorization code with PKCE and a loopback
  redirect, or a device code. The secrets service is not a login hub: other servers (a DuckDB node
  behind a gateway, a data platform) need identity-provider tokens too, and one login mints them for
  each audience.
- Services log in with their own credentials — client credentials, a private-key JWT, or a federated
  workload assertion — never with a stored person's token.
