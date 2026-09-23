# Spec 009: under an acl session, the delegated secret where there is one, the node's elsewhere

- **Status**: implemented
- **Date**: 2026-09-23
- **Author**: VGSML (with Claude)
- **Supersedes**: in part, spec 008's "a statement under a session gets its user's secrets or none"

## Summary

On a duckdb-acl node a user's statement needs two kinds of credentials:
- **delegated ones,** for what the user reaches as themselves: an http API, another acl node through
  quack. They go through the session's grant;
- **the node's own,** for what the node serves: its ducklake (the object store and the metadata
  database), its iceberg catalogs, its attached databases. The user never sees these.

Spec 008 served only the first kind under a session. A ducklake catalog of the node then failed for
every user, or needed a grant on its bucket, which would hand users the raw files. This spec keeps
the delegated secret wherever one covers the path and serves the node's own everywhere else.

## Where it applies

Only to a statement that duckdb-acl runs under a session, looked up through an attachment with the
node's **service login** (a `SECRET` of flow `client_credentials`). **In every other case the
ordinary rule holds, unchanged:**
- an attachment with a person's login serves that person's secrets;
- a node's own work, outside any session, is served the node's.

## Design

A secret lookup under an acl session (`LookupSecret`, `GetSecretByName`, `duckdb_secrets()`, and
httpfs's refresh through the tresor provider):
1. **The session's view.** The secrets the service lists under the grant are what the user may use,
   including what a rule delegates to this node for them. If one covers the path (by name: has the
   name) and its material comes back, it wins, whatever the node holds for the same path.
2. **Otherwise the node's view,** with the node's own login.

Details:
- A listed secret whose material the service refuses under the grant (`403 not_delegable`: the
  user's own secret with no rule for this node) is skipped, and step 2 applies.
- A session with no usable grant has no view, so only step 2 applies:
  - `ACT_FOR_SESSIONS` off;
  - the grant pending past `SESSION_GRANT_WAIT`, failed, refused, or expired;
  - acl's state stamped with another contract version.
- **Explicit calls are unchanged.** `corp.whoami()`, `corp.secrets()`, writes and the management
  functions under a session are the user's, through the grant, or refused. They never run as the
  node, because they show or change the service's state.

**Across attachments.** "Delegated first" holds within one attachment. Suppose two service-login
attachments cover the same path, one with a delegated secret and the other with its own. DuckDB's
own rule decides between them (the longest scope, then the storages' tie-break). Under a session,
every service-login attachment serves its own secrets where it has no delegated one. Keep one
attachment per service on a node.

`duckdb_secrets()` under a session lists the session's secrets, then the node's under other names.

### What delegates a secret

The secret's owner decides, with a delegation rule (spec 007): "this node may act for these users".
Nothing on the node chooses it, and there is no scope list to keep in step with the service.

## Enforcement & security

- **The boundary for the node's secrets is acl's gate, not the credentials.** Under a session, the
  node's secrets serve any path they cover. A user who could name such a path directly would get
  them: `read_parquet('s3://<lake bucket>/…')`, `COPY`, `ATTACH`, a replacement scan, or any
  extension's function that fetches a URL. acl's function gate closes those (its `readers`
  category is nobody's by default, and a function in no category is refused). The node's paths are
  then reached only through the catalogs acl serves. Opening `readers` to users opens the node's
  paths to them.
- **Delegated before the node's, on overlap.** If the user's delegated secret and the node's both
  cover a path, the delegated one serves: the owner's rule is the explicit decision. Without a
  usable grant, the node's would serve that path. So do not give the node its own secret on the
  scopes you delegate.
- **The delegated secret's material** still comes only through the grant, and the grant's rules on
  the service (spec 007) still apply.

## Testing

`test/sql/attach/actor.test` (the fake's `acting` realm gains `infra_lake`, the node's alone). Under
a session:
- `s3://infra` is served the node's `infra_lake` (by path and by name);
- `s3://acting`, covered by both, is served the delegated `alice_lake`;
- `shared_lake` has the user's material, not the node's;
- with no usable grant (closed, never opened, another issuer, IdP or service refusal, the grant
  rejected, a contract mismatch), lookups are served the node's secrets;
- explicit calls stay refused with their reasons, and writes and management stay the user's.

## Follow-ups

- spec 010: `mode: user` delegation in the reference server. The service exchanges the session's
  token for a downstream audience, keeps the refresh token with the grant, and serves the
  delegated secret (http `bearer_token`, quack `TOKEN`) as a dynamic one with a fresh access token.
