# Spec 012: one login for a person — the refresh token in the OS keychain, per service

- **Status**: implemented
- **Date**: 2026-09-24
- **Author**: VGSML (with Claude)

## Summary

A person's browser or device login keeps its **refresh token in the operating system's credential
store** (duckdb-ext-common spec 010, `keychain/`), keyed by the identity provider, the public
client and **the service**. The next ATTACH of that service, in the same or a later DuckDB process,
skips the browser.

Another service behind the same IdP gets its own login. That is one browser round, quick while the
IdP's session lives. It never gets a token refreshed for it silently from another service's login
(the owner's decision, 2026-09-24, after the review's H2). `tresor_logoff(...)` removes the entry and asks the IdP to revoke it.
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

- **Service and account.**
  - The keychain service is `duckdb-tresor`.
  - The account is the length-prefixed (issuer without a trailing slash, client_id, service
    `host[:port][/base]`). The client is the public one from the discovery (`issuers[].client_id`).
- **Why per service.** A service names its issuer, client and scopes in its own discovery. Were the
  key (issuer, client) alone, a hostile service behind the same IdP could name another service's
  scope, have tresor refresh the shared token for it, and receive that service's access token at its
  own whoami, with no browser and nothing visible. Keyed per service, a new service is a login the
  person sees.
- **The value.** One value per account: a version, the subject (as whoami named it) and the refresh
  token.
  - It is written right after a login, rewritten on every rotation, and removed on `invalid_grant`.
  - A session adopts a stored token only when the subject is its own: a logoff and another
    person's login elsewhere never turn a live session into that person.
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
- `CALL tresor_logoff(service := '…', issuer := '…', client_id := '…')`: one by name, attached or
  not.
- `CALL tresor_logoff()`: every remembered login attached here. A `REMEMBER false` attachment is
  left alone. The store is not enumerated: a listing API differs on every platform, and a name is
  enough.
- It is refused for a statement run under a duckdb-acl session: a session's user must not end the
  node's people's logins.
- What it does, in this order:
  1. ends the attached sessions remembered under that key, so that no renewal can store it back;
  2. removes the entry;
  3. revokes every distinct refresh token (the stored one and the sessions') at the IdP, when the
     discovery (OIDC) names a `revocation_endpoint` (RFC 7009, as the public client), best effort.
- It returns one row per login: (service, issuer, client_id, removed, revoked). It never returns a
  token.
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
  issuer is part of the entry's key; a token is never sent to an issuer other than the one it is
  stored under.
- **Which service gets its tokens.** Only the service the login was made for, since the key has the
  service in it. A service cannot obtain a token refreshed from another service's login.
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

## The review's findings (applied)

- **HIGH H2: another service behind the same IdP and client got tokens for this one, silently.** Now
  the key is per service (the owner's decision); see "Why per service".
- **HIGH H1: `memory` and `off` still reached the OS store on a remove.** Now only `auto` ever
  touches it; `memory` and `off` never do.
- **HIGH H3: a remembered session renewed without its scope.** The renewal now asks for this
  service's scope, for every person flow.
- **Rotation.**
  - A chain is renewed by one caller at a time in the instance (a lock per key).
  - A renewal first re-reads the stored token, which another session or process may have rotated.
  - A rotated token is stored at once, even when the service then refuses the login.
  - A dead token is removed only if it is still the stored one.
  - A remembered session stores what it holds, not what the login returned.
- **`tresor_logoff`.**
  - It ends the sessions first, so no renewal stores the token back.
  - It revokes each distinct token.
  - It touches remembered logins only, and `removed` comes from what was found.
  - It is refused under an acl session.
  - A logout is audited only when something was forgotten.
- **Smaller fixes:**
  - the account key is length-prefixed;
  - the loopback check parses the host;
  - a login remembered in `memory` never reaches the OS store after a switch to `auto` (the mode is
    fixed when the login is remembered);
  - an invalid `TRESOR_KEYCHAIN` names itself;
  - the docs cover the account switch, a detached catalog (use the named form), and the host
    program's access on macOS.
- **Not taken:**
  - keychain I/O runs under the session's lock during a renewal (at most once per token lifetime);
  - the whoami probe's timeout is fixed at 30 s.

### The re-review's findings (applied)

- **MEDIUM: a live session could adopt another person's login.** It did so when that login was stored
  under its key since, through a logoff and a login as someone else elsewhere. Now the stored
  value carries the subject, and a session adopts only its own.
- **MEDIUM: the mode was fixed for Store only.** Load and Remove now name the mode too: a login
  remembered in memory never reads or removes in the OS store after a switch to auto.
- **MEDIUM: a remembered login's first store could overwrite a newer token.** Another attachment
  may have rotated the token between the refresh and the whoami. `Remember` now runs under the key's
  lock and stores only if the entry is still the token it began with. A fresh login still replaces
  the entry.
- **Smaller fixes:**
  - `tresor_logoff` takes the key's lock (after ending the sessions, in their order);
  - a revocation endpoint found by an unattached logoff must be https or loopback;
  - after `invalid_grant`, a renewal retries once with a newer token another process stored;
  - the no-op `acl_stub_open` is gone from the test.
- **The key lock is this process's.** Across processes the re-read and the compare-and-delete are
  what keep two DuckDB processes from spoiling one chain; a rotating IdP with reuse detection can still end
  both, which a new login mends.

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

- **`test/sql/attach/remember.test`** (fake IdP, 74 assertions), with the fake counting its
  `/authorize` visits, refreshes (and their scope) and revocations:
  - one browser visit serves this service and a later ATTACH of it, refreshed in exactly its scope;
  - another service of the same IdP gets its own browser login, and is then remembered apart;
  - `REMEMBER false`;
  - a service login refused `REMEMBER` and `tresor_logoff`;
  - a service that refuses the refreshed token (the fake's `picky`) gets a browser login;
  - `tresor_logoff` is refused under an acl session (acl_stub);
  - `tresor_logoff('b')` removes, revokes and ends that login only: another service's login and a
    `REMEMBER false` one are untouched;
  - `tresor_logoff()` takes the other remembered one;
  - the next ATTACH opens the browser;
  - the IdP forgetting its tokens makes the next ATTACH a browser login;
  - logoff by name needs all three (service, issuer, client_id), and revokes through the issuer's own
    discovery;
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
