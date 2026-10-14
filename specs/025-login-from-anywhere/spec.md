# Spec 025: a person logs in from any client - tresor_login, logoff that detaches, switching identity

- **Status**: implemented
- **Date**: 2026-10-14
- **Author**: hugr lab
- **Asked by**: the owner: an analyst works from DuckDB UI, Python/Jupyter, DBeaver and other IDEs, not only the
  CLI

## Summary

A person's login runs inside `ATTACH` today, and what it shows - "log in in your browser - if it did not open,
visit ..." and a device code - goes to the process's stderr. In the CLI that is in front of the person; in DuckDB
UI, a notebook or DBeaver's JDBC driver nobody sees it. On a desktop the browser opens by itself, so it mostly
works; a remote kernel or a container (device flow) cannot show its code at all. And `tresor_logoff` leaves the
catalogs on that login dead until `DETACH` and `ATTACH`.

- **`tresor_login(...)`**: a person's login as a query of its own, which answers at once with the URL to open and
  the device code - a row any client shows - and completes in the background. `ATTACH` then finds the login.
- **`tresor_logoff` detaches** the catalogs on the login by default; `detach := false` keeps them, waiting for a
  new login, which they take up - the same person or another (switching identity), their caches dropped.
- **`prompt`**: a new login can ask the identity provider to pick or re-enter the account, so that its browser
  session does not silently log the same person in again.

## Design

### `tresor_login(target [, login, issuer, insecure_http, remember, prompt])`

```sql
FROM tresor_login('tresor:secrets.corp');
-- service | issuer | client_id | flow | status | url | user_code | expires_at
FROM tresor_login('corp', prompt := 'select_account');   -- an attached catalog: its service's login
```

- **The target** is a service (`tresor:host[:port][/base]`, read as ATTACH reads it, with `issuer` and
  `insecure_http` as ATTACH's options) or an attached tresor catalog (its session's service and issuer).
- **Already logged in**: a login remembered for the key (issuer, client_id, service) answers `done` at once -
  after the service's discovery (which names the key), with no login and nothing asked of the IdP. To log in as
  someone else, `tresor_logoff` first.
- **A login in progress** for the key answers its own row again (`pending`), with the same URL and code -
  whatever options this call names (another `login`, `prompt`, `remember` do not change it; `tresor_logoff` ends
  it). Two calls at once start one login: it is registered before anything starts.
- **Otherwise it starts one** - the flow `login` names (`auto`, `browser`, `device`, as ATTACH's LOGIN) - on a
  thread of its own, and answers as soon as there is something to show:
  - browser: the authorization URL, once the loopback receiver listens; the browser is also opened, as now;
  - device: the verification URL (complete, when given) and the user code.
  - Both are also printed to stderr, as now.
- **`prompt`** is passed to the IdP's authorization request: `login` (re-enter the credentials), `select_account`
  (Entra: pick the account), `consent`, `none`. Not for the device flow, which always asks.
- **On completion** the refresh token is remembered under the key in `tresor_keychain`'s mode (the OS store, or
  memory). With `remember := false` or `tresor_keychain = 'off'`, the tokens are kept in memory for one ATTACH of
  that service only (the first; another ATTACH at once logs in by itself), and with `remember := false` that
  ATTACH does not remember them either, whatever its REMEMBER. Until the service's whoami names the person, the
  entry's subject is a placeholder no real subject is (as a handed-over login's, specs/020). An ATTACH with
  `REMEMBER false` after a login `tresor_login` remembered uses it and leaves it remembered (`tresor_logoff`
  forgets it). Kept tokens are wiped when the login is forgotten.
- **A status**: calling it again answers `pending`, `done`, or `failed: <why>` (the IdP's refusal, the deadline, a
  logoff) - a failed one is forgotten by that answer (or by the ATTACH that waited for it), and the next call
  starts anew. The call that started it never forgets a failure it reports: a failure that comes at once (the IdP
  refuses `prompt=none`) is still told to the ATTACH that follows.
- **Lifetime**: a login waits at most `LOGIN_TIMEOUT`'s default (300 s); the instance cancels its logins when it
  closes. It never returns or logs a token.
- **Refused**: under a duckdb-acl session (the node's people are not its users' to log in); in wasm (the page logs
  in, specs/020); for a catalog whose login is a service's.

### ATTACH meets a login in progress

A person's ATTACH whose key has a login in progress waits for it - interruptible, up to its `LOGIN_TIMEOUT` - and
goes on with what it left: the tokens it kept (`remember := false`), or the remembered login. A login that failed
fails the ATTACH with its reason ("the login ... that tresor_login started failed: ..."). Either way the ATTACH uses
it up. So a notebook's two cells work: `FROM tresor_login(...)` (the link shows), then `ATTACH ...` (it waits until
the person has logged in).

### `tresor_logoff(..., detach := true)`

- As today it forgets the login (the store), revokes it at the IdP where it can, and ends the sessions on it.
- **It now detaches** every catalog on that login, by default. A row says how many (`detached`). A catalog kept
  by an earlier `detach := false` and still logged off is detached by `tresor_logoff('<it>')` too (`removed` false
  when nothing was remembered since).
- **`detach := false`** keeps them: nothing held for the login is served from then on (the list, the material,
  the variables go at once), and a query on one says "logged off - log in: FROM tresor_login('corp')" (the
  catalog's name).
- **A login in progress** for the key is cancelled (`failed: logged off`) - before the store's entry is removed,
  so a login completing meanwhile stores nothing; one that already ended is forgotten, so the next
  `tresor_login` starts anew.
- A catalog DuckDB will not detach in this statement - the connection's default database (`USE corp`) - stays,
  as with `detach := false`, and its row's `detached` does not count it.

### A kept catalog takes up the next login

A catalog kept by `detach := false` finds, on its next call, a login remembered under its key since - by
`tresor_login`, an ATTACH of the same service, or another process (the OS store). A login in progress for its key
is waited for first - outside the session's lock, so other calls, a DETACH (which ends the wait) and the logoff
that cancels it go on meanwhile; up to `LOGIN_TIMEOUT`'s default, and not interruptible by the waiting query (the
service call reaches no connection):
- it renews from it - still logged off until the renewal works: a transient failure fails that call, the next
  call renews again - and asks the service's whoami (renewing once more on a 401);
- everything held is dropped again before the first answer for the login taken up (already dropped at the
  logoff): the list of secrets, the material and dynamic secrets cached, variables. A lookup that took the
  login up answers from a list fetched for it, never one fetched before;
- the store's entry is renamed from the placeholder to the person only if it is still the one taken up;
- the audit records a `login` with detail `resumed` (the same person) or `resumed_other` (another).

While logged off, each lookup asks the session (the store, a login in progress) rather than backing off: a scan
over many files reads the store once per file until a login is taken up.

A service's login (a `tresor` secret) has nothing remembered: logoff does not apply to it, as now.

## Enforcement & security

- No token in any row, message or log; the device code and the URL are what the person is meant to see.
- A logoff drops every cache of the login at once; a kept catalog serves nothing while logged off, and nothing
  fetched before a login was taken up (the storage's caches carry an epoch: a list fetched across a reset is
  neither kept nor answered). Switching identity is audited.
- The OS store as in specs/012. On macOS an item created by one program (the duckdb CLI) asks the person before
  another (Python, a JVM) reads it - checked live and documented.

## Testing

- `test/sql/attach/login.test` (the fake IdP, which now honours `prompt`: `none` answers `login_required`,
  `select_account` logs another person in - bob, who may not use alice's `lake`; `/_fail_refresh` makes the next
  refresh answer 503):
  - `tresor_login` answers at once with a URL (browser) and a code (device); ATTACH waits for one in progress and
    uses it (one authorization); `done` when already logged in;
  - logoff detaches by default (`detached`); `detach := false` keeps the catalog: a lookup that found alice's
    `lake` before finds nothing after the logoff (no cache hit), a call says "log in: FROM tresor_login('corp')";
  - switching identity: after `tresor_login('corp', prompt := 'select_account')` the first lookup takes up bob's
    login and finds nothing for alice's path but bob's `lake_team_a`; whoami names bob; `resumed_other` audited;
    the prompt reached the IdP;
  - an IdP outage while a kept catalog takes up a login fails that call, and the next one goes on (alice);
  - `tresor_logoff('corp')` detaches a kept catalog still logged off (`removed` false, `detached` 1);
  - an IdP's refusal (`prompt := 'none'`) fails the ATTACH that follows, whoever saw the failure first;
  - `remember := false`: the ATTACH that takes the tokens does not remember them, with `REMEMBER false` or
    REMEMBER's default (the next ATTACH logs in anew);
  - a logoff ends a login in progress (`failed: logged off`);
  - the connection's default database (`USE corp`) is not detached and stays logged off; a later logoff detaches
    it;
  - refusals (unknown target, prompt, option, an acl session, a service's catalog).
- `remember.test` and `web_login.test`: logoff's `detached` column; `detach := false` where a test goes on with
  the catalog.
- Not covered by a sqllogictest (one connection, no concurrency): a logoff or DETACH ending a kept catalog's wait
  for a login in progress, two ATTACHes (or two `tresor_login` calls) racing for one login, a login completing
  while a logoff runs. These follow from the lock discipline above and were reviewed, not tested.
- Live, by the owner (tests never touch the OS store): the macOS keychain read from Python and DBeaver after a
  login in the CLI - the expected one-time "allow" prompt is documented.
- Docs: `website/docs/clients.md` ("From DuckDB UI, Python and IDEs"); `getting-started.md` for logoff's detach
  and switching identity.

## Implementation

- `src/tresor_pending.cpp`: the instance's logins in progress (`PendingLogins`, an ObjectCache entry), a thread per
  login on the setting's HTTP client, cancelled and joined when the instance closes. Registered before it starts
  (`FindOrAdd`); removed by identity (`Remove(login)`), never a newer login for the key; kept tokens wiped with it.
- `src/tresor_login_function.cpp`: the table function; `StartPersonLogin` in `tresor_login.cpp` (with the person's
  flow choice and the issuer's resolution shared with ATTACH).
- `TresorSession`: a logged-off session takes up the next login (`TakeUpLogin`, renewed - `taken_up` until that
  works -, then a whoami); `LoggedOff()` for the storage; `OnLoggedOff` / `OnResumed` empty the catalog's storage
  (`TresorSecretStorage::ResetCaches`) and the latter audits it; the wait for a login in progress (`OnPendingLogin`)
  runs in `Call` before the lock is taken. `Subject()` is a copy under the lock.
