# Spec 012: one login for a person — the refresh token in the OS keychain, shared by services of one IdP

- **Status**: implemented
- **Date**: 2026-09-24
- **Author**: VGSML (with Claude)

## Summary

A person's browser or device login keeps its **refresh token in the operating system's credential
store** (duckdb-ext-common spec 010, `keychain/`), keyed by the identity provider and the public
client. The next ATTACH skips the browser when that key already holds a live refresh token. This
covers:
- the same service, in the same or a later DuckDB process;
- any other service whose discovery names the same issuer and client.

That is single sign-on. `tresor_logoff(...)` removes the entry and asks the IdP to revoke it.
Service logins (`client_credentials`, `token`) — duckdb-acl nodes among them — never touch the
keychain.

## Problem

- **Every process asks again.** Every new DuckDB process opens the browser, as does every ATTACH
  of another service behind the same IdP. The IdP's own session makes the browser step quick, but
  it is still a browser step: it cannot run in a script or a notebook kernel, and it cannot run
  over SSH without the device flow.
- **Memory is the only store today.** The refresh token that would avoid this exists, and tresor
  drops it at DETACH or when the process ends.

## Design

### The rule this changes (the owner's decision, to be recorded in CLAUDE.md)

"Never write secret material to disk" gains one exception:
- only a **person's refresh token**;
- only in the **OS credential store**;
- never a file, and never anything else (access tokens, grants, material, service credentials).

### What is kept, and under which key

- **Service and account.** Keychain service `duckdb-tresor`; account
  `<issuer, no trailing slash> <client_id>`. The client is the public one from the discovery
  (`issuers[].client_id`).
- **The value.** One value per account: the refresh token. It is written right after a login,
  rewritten on every rotation, and removed on `invalid_grant`.
- **Nothing else is stored.** Scope, audience and expiry are re-derived at each use; the IdP knows
  the token's lifetime.

### ATTACH with a remembered login

For a person login (`LOGIN` browser/device/auto, no service secret), when the keychain holds an
entry for the chosen (issuer, client):

1. **Refresh.** tresor sends a refresh grant at the issuer's token endpoint with **this
   service's** scope (the discovery's scopes for the issuer), as the public client.
2. **Is it for this service?** One plain `GET /v1/whoami` with the new access token, without the
   usual renew-and-retry.
   - 401: another audience, or a scope this IdP will not widen. The person's login runs, and its
     refresh token replaces the entry.
   - Accepted: the session runs on it and renews from it as today; a rotated refresh token replaces
     the entry.
3. **Refresh failures.**
   - `invalid_grant`: the entry is removed and the normal login runs.
   - Another refusal (`invalid_scope`, …): the normal login runs.
   - A network failure (at the IdP or at the whoami): an error, as a login's would be. No browser
     opens for a passing outage.

### Options

- **`REMEMBER`** (ATTACH): `true` by default for person logins where a keychain is available.
  `false` neither reads nor writes the keychain for this ATTACH.
- **`TRESOR_KEYCHAIN`** (environment) sets the setting's default: `off` on a CI runner or a shared
  account, `memory` in the test scripts, which therefore never touch the OS store. It can only
  narrow: `auto` is the default anyway.
- **`tresor_keychain`** (GLOBAL setting; `SET SESSION` is refused, since the store is the instance's):
  - `auto` (default): the OS store where available, nothing otherwise;
  - `off`: never;
  - `memory`: an in-process store, gone with the process. For tests and for a notebook kernel
    that wants SSO within one process; nothing leaves memory.
- **The login flow.** `whoami()`'s `login` says `remembered`. The session renews as a browser or
  device login does, from the refresh token.

### `tresor_logoff`

- `CALL tresor_logoff('<catalog>')`: the entry of that attachment's (issuer, client).
- `CALL tresor_logoff(issuer := '…', client_id := '…')`: one by name.
- `CALL tresor_logoff()`: the login of every person attachment here.
  - Entries of logins not attached in this instance are removed by name.
  - The module does not enumerate the store: a listing API differs on every platform, and a name is
    enough.
- What it does:
  - removes the entry;
  - revokes the refresh token at the IdP when the discovery (OIDC) names a `revocation_endpoint`
    (RFC 7009, as the public client), best effort;
  - marks the attached sessions using that key as logged out (their next renewal asks for a new
    ATTACH).
- It returns one row per login: (issuer, client_id, removed, revoked). It never returns a token.
- It refuses a service's attachment by name ("nothing of it is remembered, DETACH ends it").
- Unattached, by issuer: the revocation endpoint comes from the issuer's own discovery, https or
  loopback only.

### Nodes and services

- **Service logins never use the keychain:**
  - `client_credentials` re-mints from the client secret, and a `token` login has no refresh;
  - `ACT_FOR_SESSIONS` requires `client_credentials` (spec 008);
  - `REMEMBER true` on a service login is refused.
- **Sessions acted for are untouched:** nothing an acl session brings is ever stored.
- **Static client secrets on nodes** are the next spec's subject (013: `private_key_jwt`,
  federated assertions, Azure managed identity), not this one's.

### Audit (spec 011)

- A remembered login is a `login` event with `detail = remembered`.
- `tresor_logoff` is a `logout` event with `detail = logoff`, or `logoff_revoked` when the IdP
  confirmed.
- No token is ever in an event.

## Enforcement & security

- **Where the token may be.** In memory, and in the OS store under the rules of ext-common
  spec 010:
  - never a file tresor writes;
  - never iCloud on macOS, where the login keychain file does travel with a backup;
  - never roaming on Windows;
  - on Linux, wherever the Secret Service provider keeps its collection;
  - on macOS, guarded per host program.
- **Where it may go.** Only to its issuer's token endpoint, and to the revocation endpoint. The
  issuer is the entry's key and the discovery's choice of issuer; a token is never sent to an
  issuer other than the one it is stored under.
- **Is it meant for this service?** Its access token proves that at whoami, as a fresh login's
  does. A service cannot obtain another service's token: the refresh happens at the IdP, and the
  IdP bounds the scope and audience.
- **What the store protects.** Another process of the same OS user (Linux, Windows) can read the
  entry. That is the OS's model for every desktop application, and it is documented in
  security.md. `REMEMBER false` or `tresor_keychain = 'off'` for anyone who does not accept it.
- **A shared machine account** (a CI runner, a jump host) should set `tresor_keychain = 'off'`. The
  docs say so.

## Testing

- **sqllogictests (fake IdP), with `tresor_keychain = 'memory'`:**
  - a login is remembered, and a second ATTACH (and one to another service of the same fake IdP)
    opens no browser — the fake browser counts its visits;
  - rotation replaces the entry — the code path is there, but the fake IdP does not rotate
    (Keycloak does not by default either), so it is not exercised;
  - `invalid_grant` removes it and the browser runs;
  - a 401 at whoami falls back to the browser, and the new token replaces the entry;
  - `REMEMBER false` neither reads nor writes;
  - a service login never writes (the memory store is empty);
  - `tresor_logoff` removes the entry, revokes it at the fake's `revocation_endpoint` (recorded),
    and a live session's next renewal fails;
  - no token in `duckdb_logs`, whoami or `tresor_logoff`'s rows.
- **Keycloak, with the real OS store** (Linux CI: gnome-keyring in `dbus-run-session`):
  - two separate DuckDB processes: the first logs in through `browser.py`, the second attaches
    with no browser (`BROWSER=false`, which would fail);
  - two services of the realm share one login;
  - `tresor_logoff` removes the entry, and Keycloak's revocation ends the refresh token (the next
    process's refresh gets `invalid_grant`).

## What the tests found

- **A test run reached the real macOS keychain.** The fake IdP's person logins were stored under
  `http://127.0.0.1:<port>/idp duckdb`, and in the owner's session the system showed a "Keychain
  Not Found" dialog, with no default keychain at that moment.
  - The test scripts now set `TRESOR_KEYCHAIN=memory`.
  - The module (ext-common spec 010) treats a missing default keychain as unavailable, so the
    system dialog never shows.
  - Where the flows themselves are tested, the tests set `tresor_keychain = 'off'`.
- **A refused remembered token needs its own check.** The session's renew-and-retry turned the
  service's 401 into an error. So the check is one plain whoami before the session exists.

## Checked

- **`test/sql/attach/remember.test`** (fake IdP, 62 assertions), with the fake counting its
  `/authorize` visits, refreshes (and their scope) and revocations:
  - one browser visit serves this service, a later ATTACH and another service of the IdP, asked in
    its own scope;
  - `REMEMBER false`;
  - a service login refused `REMEMBER` and `tresor_logoff`;
  - a service that refuses the refreshed token (the fake's `picky`) gets a browser login;
  - `tresor_logoff('b')` removes and revokes the login, and ends both attachments on it;
  - the next ATTACH opens the browser;
  - the IdP forgetting its tokens makes the next ATTACH a browser login;
  - logoff by name;
  - `off`;
  - the audit's `remembered` and `logoff_revoked`, with no token in the log.
- **`test_keycloak.sh`, `TRESOR_KC_KEYCHAIN=1`** (CI: Linux, gnome-keyring on the step's session
  bus; locally: the owner's macOS Keychain), in four DuckDB processes:
  1. a login through Keycloak's browser form;
  2. a second process with `BROWSER=false` is logged in by the remembered login;
  3. `tresor_logoff` removes it and Keycloak revokes it;
  4. a fourth process has no login without a browser.

  The store is empty afterwards.

## Follow-ups

- Entra: a refresh token of the public client can mint tokens for other resources (the `scope`
  names them). The same path covers it; checked live in spec 013 against the owner's tenant.
