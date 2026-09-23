# Spec 009: under an acl session, the node's secret on its own paths, the delegated one elsewhere

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
every user, or needed a grant on its bucket, which would hand users the raw files. This spec serves
the node's own secret on the paths it covers, and the delegated one on every other path.

## Where it applies

Only to a statement that duckdb-acl runs under a session, looked up through an attachment with the
node's **service login** (a `SECRET` of flow `client_credentials`). **In every other case the
ordinary rule holds, unchanged:**
- an attachment with a person's login serves that person's secrets;
- a node's own work, outside any session, is served the node's.

## Design

A secret lookup under an acl session (`LookupSecret`, `GetSecretByName`, `duckdb_secrets()`, and
httpfs's refresh through the tresor provider):
1. **The node's view,** with the node's own login. If one of its secrets covers the path (by name:
   has the name), it serves. The paths of the node's catalogs are the node's: no secret of a user's
   can redirect them. This step never waits for the session's grant.
2. **Otherwise the session's view:** the secrets the service lists under the grant (what the user
   may use, including what a rule delegates to this node for them). The best-scoped one whose
   material comes back serves.
   - A listed secret whose material the service refuses under the grant (`403 not_delegable`: the
     user's own secret with no rule for this node) is skipped for the next candidate. It is
     remembered, by name and version, for the session: neither the list nor later lookups pay for
     it again.
   - A session with no usable grant has no view, so it finds nothing here: `ACT_FOR_SESSIONS` off;
     the grant pending past `SESSION_GRANT_WAIT`, failed, refused or expired; acl's state stamped
     with another contract version.
- **Only a service login serves the node's view under a session.** An attachment with a person's
  login serves nothing under a session: neither their secrets nor anyone's.
- **Explicit calls are unchanged.** `corp.whoami()`, `corp.secrets()`, writes and the management
  functions under a session are the user's, through the grant, or refused. They never run as the
  node, because they show or change the service's state.

`duckdb_secrets()` under a session lists the node's secrets, then the session's under other names:
the order lookups by name take. Users therefore see the names and scopes of the node's secrets, but
acl's gate keeps `duckdb_secrets()` from principals.

**Across attachments.** The node-first order holds within one attachment. Two service-login
attachments covering one path are decided by DuckDB's own rule (the longest scope, then the
storages' tie-break: the first registered wins). Keep one attachment per service on a node.

### What delegates a secret

The secret's owner decides, with a delegation rule (spec 007): "this node may act for these users".
Nothing on the node chooses it, and there is no scope list to keep in step with the service. A
delegated secret on a path the node also covers is not served: the node's wins there. To have a
user's secret serve a path, do not give the node its own.

## Enforcement & security

- **The boundary for the node's secrets is acl's gate, not the credentials.** Under a session, the
  node's secrets serve any path they cover. A user who could name such a path directly would get
  them: `read_parquet('s3://<lake bucket>/…')`, `COPY`, `ATTACH`, a replacement scan, or any
  extension's function that fetches a URL. acl's function gate closes those (its `readers`
  category is nobody's by default, and a function in no category is refused). The node's paths are
  then reached only through the catalogs acl serves. Opening `readers` to users opens the node's
  paths to them.
- **Node first, so no user can redirect the node's paths.** Suppose a delegated secret won. A user
  who may create and delegate secrets could put one on the node's lake bucket (`SCOPE
  's3://<bucket>'`, an `ENDPOINT` of theirs) and delegate it to the node for themselves. The node's
  ducklake writes, in that user's session, would then land on the user's endpoint while its
  metadata commits them to the shared catalog. Scope length does not help, since a longer scope can
  always be written. With the node first, a user's secret serves only paths the node has no
  secret for.
- **With no usable grant,** the node's paths are still the node's, and every other path finds
  nothing. A delegated secret is never served with the node's identity.
- **The delegated secret's material** still comes only through the grant, and the grant's rules on
  the service (spec 007) still apply.
- **A contract mismatch** (acl built from another `acl_connection` version) is served as a session
  without a grant: the node's paths, nothing else, and explicit calls refused.
- **A new session's first statements** do not wait for the grant on the node's paths. Only
  delegated paths wait, up to `SESSION_GRANT_WAIT`.

## Testing

`test/sql/attach/actor.test`. The fake's `acting` realm gains `infra_lake` (the node's alone),
delegated secrets on `s3://alice`, and `alice_own`, listed for alice but not delegated. Under a
session:
- the node's paths (`s3://infra`, and `s3://acting`, which a delegated secret cannot take) are served
  the node's secrets, by path and by name;
- `s3://alice` is served the delegated `alice_lake`;
- a longer-scoped refused secret (`alice_own`) is skipped for the next candidate;
- `duckdb_secrets()` lists the node's names, then the delegated ones;
- a person's attachment serves nothing;
- with no usable grant (closed, never opened, another issuer, IdP or service refusal, the grant
  rejected, a contract mismatch), lookups are served the node's secrets only;
- explicit calls stay refused with their reasons, and writes and management stay the user's.

## The review's findings (applied)

The first version served the delegated secret first. An independent review found:
- **A user could redirect the node's paths** with a delegated secret on them (see above). The order
  is now node first.
- **A person's attachment served that person's secrets to every session.** Now only a service login
  serves the node's view under a session.
- **A refused delegated secret** hid shorter-scoped delegated ones, marked the list stale (two
  requests per file of a scan), and made httpfs's refresh take another branch than the lookup. It
  is now skipped for the next candidate, remembered by version, and the refresh follows the lookup's
  order.
- **The node's paths waited for the session's grant.** They no longer do.
- **Docs.** The security page contradicted itself about the confused deputy, and the website left
  out the per-attachment rule and what `duckdb_secrets()` shows. Both are fixed.

## Follow-ups

- spec 010: `mode: user` delegation in the reference server. The service exchanges the session's
  token for a downstream audience, keeps the refresh token with the grant, and serves the
  delegated secret (http `bearer_token`, quack `TOKEN`) as a dynamic one with a fresh access token.
