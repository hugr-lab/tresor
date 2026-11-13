# Spec 047: TOKEN_FILE - the service's bearer token from a file a platform rotates (SPIFFE path B)

- **Status**: implemented (2026-11-13)
- **Date**: 2026-11-13
- **Author**: hugr lab
- **Asked by**: the owner (2026-11-12, through tresor-server's spec 038): SPIFFE "path B" - the secrets service
  trusts SPIRE as an issuer, and a workload's JWT-SVID is its bearer token, with no identity provider in between

## Summary

`FLOW 'token'` takes a token already held, `TOKEN`, and never renews it. **`TOKEN_FILE`** names a file that holds the
token instead: it is read at the login, again a minute before the token expires and again after a 401, so a token the
platform rotates (spiffe-helper's JWT-SVID, every few minutes) is picked up. With **`SPIFFE_ID`** the file holds a
JWT-SVID, checked as specs/046 checks one - against the service instead of an identity provider. That is the client
side of tresor-server's spec 038: the service trusts SPIRE's OIDC discovery as an issuer and gives a workload its roles
by its SPIFFE ID.

## Problem

A SPIFFE workload logs in today through an identity provider (specs/046: Keycloak's `jwt-spiffe`, or Entra's
federation by `jwt-bearer`). A service that trusts SPIRE itself needs neither: the SVID is the bearer. But
`FLOW 'token'` holds one token for the life of the ATTACH, and an SVID lives 5 minutes; and nothing checks that the
token is for this service before it is sent.

## Design

- **The secret**: `FLOW 'token'` takes exactly one of `TOKEN` and `TOKEN_FILE`, and `SPIFFE_ID` only with
  `TOKEN_FILE` (the `spiffe://` check of specs/046). A persistent secret read back (not validated again) that names
  both `TOKEN` and `TOKEN_FILE`, or `SPIFFE_ID` without `TOKEN_FILE`, is refused at the login.
- **The issuer** (no IdP is contacted): a JWT's `iss` picks the discovery's issuer - one the service lists, or the
  login is refused ("does not accept the issuer"); a JWT without `iss` takes the one issuer listed, or the ATTACH's
  `ISSUER`. An `ISSUER` other than the token's `iss` is refused. That issuer's `audience` is what the token must carry;
  an issuer listed without one is refused for a JWT. The login reads the file once: the issuer is chosen from the
  token that is checked and sent (`CheckToken`).
- **The checks, at every read** (`ServiceCredential::ReadToken`, `Kind::TOKEN_FILE`):
  - with `SPIFFE_ID`, or when the file holds an SVID (its `sub` a SPIFFE ID): the checks of specs/046 (one function
    for both, `SvidRefusal`) - a JWT, `sub` = `SPIFFE_ID` (an SVID without `SPIFFE_ID` is refused, as in 046), `aud`
    the service's audience (trailing slashes do not count), an `exp` in the future;
  - any other JWT: `aud` the service's audience, `exp` (when it has one) in the future;
  - a JWT's `iss`, when it has one, the issuer the login chose;
  - an opaque token: the service alone judges it, as `TOKEN`'s - unless the login's was a JWT: then a file that holds
    no JWT now (a torn write, another kind of token) is refused, and one that holds a JWT after an opaque login too
    (ATTACH again).
  A token that fails is wiped and never sent; the error names the path and what is wrong, never the token.
- **Renewal** (`TresorSession::AccessToken`): `LoginFlow::TOKEN` with a token file reads it again where the other
  service flows mint again - a minute before `exp` (half the life for short ones) and after a 401. `TOKEN` is still
  never renewed.
- **The file**: `ReadCredentialFile` as for an assertion file (a regular file, at most 64 KiB, trailing whitespace
  dropped, not required to be private: it is short-lived and audience-bound), inside DuckDB's sandbox
  (`CheckAccess`).
- `whoami()`'s `login` is `token`. `ACT_FOR_SESSIONS` still needs a client at the IdP (unchanged).
- **No protocol change.** No duckdb-ext-common change.

## Enforcement & security

- An IdP token goes only to its audience: a JWT from the file for another audience, from an issuer the service does
  not list, or expired, is never sent. An SVID is sent only as the workload named.
- The audience is the service's discovery's, as for the IdP flows (no `AUDIENCE` pins it, unlike a managed
  identity's): the secret's `SCOPE` decides which service that is, and a JWT for several audiences reaches it. No worse
  than `TOKEN`, which is not checked at all.
- The file is read on every renewal: a revoked or replaced SVID is not cached beyond its own expiry.
- Nothing new is kept: the token lives in the session, as a minted one does.

## Testing

- `test/sql/attach/token_file.test` against the fake service, which takes a JWT for `duckdb-secrets` from its issuer
  as the bearer (`held_identity`; a claim `uses` caps how often whoami takes it): the secret's rules; an SVID with and
  without `iss`; a rotation - the first SVID refused after its use, the file's new one taken after the 401; refused
  before sending - for the IdP, another issuer, `ISSUER` not the token's, another workload, expired, without `exp`, an
  SVID without `SPIFFE_ID`, `SPIFFE_ID` with an opaque file, a missing file; a platform's JWT for the service, for
  another audience, expired; an opaque token from a file; after a 401 - an opaque token where the login's was a JWT,
  an SVID from another issuer than the login's; the sandbox. Also on DuckDB's HTTP client (`TRESOR_HTTP_CLIENT=duckdb`).
- Not tested here: the read a minute before `exp` (a sqllogictest cannot wait for it). It is the path every service
  flow renews on (`AccessToken`'s margin); the 401 path, tested, reads the file the same way.
- Live: tresor-server's `scripts/dev/spire_live.sh up|check` (SPIRE 1.13.0, SVIDs of 5 minutes).

## Alternatives considered

- **`ASSERTION_SOURCE 'spiffe'` on `FLOW 'token'`**: the token is no assertion here; a file of the service's own
  token is the general thing (a Kubernetes token the service trusts, any platform's), and SPIFFE adds a check.
- **Leaving `TOKEN` as is and documenting a re-ATTACH**: an SVID lives minutes.
- **Checking `TOKEN` too**: its JWT is not checked today; changing that is a separate decision (follow-up).

## Follow-ups

- Check a JWT `TOKEN` the same way (`aud`, `iss`, `exp`) before it is sent.
- The SPIFFE Workload API (a socket) instead of spiffe-helper's file.
