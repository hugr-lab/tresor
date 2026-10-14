---
sidebar_position: 2.5
title: From DuckDB UI, Python and IDEs
---

# From DuckDB UI, Python and IDEs

A person's login runs inside DuckDB, wherever DuckDB runs: the DuckDB CLI, DuckDB UI, Python (a
script, Jupyter, VS Code), an IDE's JDBC driver (DBeaver, DataGrip), or an application that embeds
DuckDB. Three things make it work everywhere.

**The browser opens from DuckDB's own process.** tresor opens the system browser and waits for the
identity provider's answer on a loopback port. It does not matter which program hosts DuckDB, as long
as it runs on the person's machine.

**One login serves every program.** The refresh token is kept in the operating system's credential
store, under the service's key. Log in once - from any of them - and every DuckDB process of the same
person on that machine attaches with no browser, until the identity provider ends the login.

**`tresor_login` shows the link where stderr shows nowhere.** In the CLI, the link and the device
code are printed to the terminal. DuckDB UI, a notebook or an IDE does not show a process's stderr, so
log in with a query of its own:

```sql
FROM tresor_login('tresor:secrets.corp.example');
-- service | issuer | client_id | flow    | status  | url                         | user_code | expires_at
--         |        |           | browser | pending | https://login.../authorize… |           | …
ATTACH 'tresor:secrets.corp.example' AS corp;   -- waits until the login completes, then attaches
```

- It answers at once and completes in the background. The browser also opens by itself where it can.
- `login := 'device'` takes the device flow. The row then carries the code to enter, and its `url`
  is the page to enter it on.
- An `ATTACH` of that service while the login is in progress waits for it, up to `LOGIN_TIMEOUT`.
- Called again, it answers the login's status: `pending`, `done`, or `failed: <why>`. Already logged
  in, it answers `done` at once. A call while a login is in progress answers that login, whatever
  options it names: to start another one, `tresor_logoff` first.
- A failed login is told once more, to the `ATTACH` (or the call) that asks after it; then it is
  forgotten, and the next `tresor_login` starts anew.
- `remember := false` keeps the login for the next ATTACH only, in this process: that ATTACH does not
  remember it either. (`REMEMBER false` on the ATTACH does not undo a login `tresor_login` already
  remembered: `tresor_logoff` does.)
- It also takes an attached catalog's name: `FROM tresor_login('corp')`.
- It never returns a token.

## Per tool

| Where DuckDB runs | Logging in |
| --- | --- |
| DuckDB CLI | `ATTACH` - the browser opens, the link is printed |
| DuckDB UI (`duckdb -ui`, `CALL start_ui()`) | `ATTACH` - the browser opens in a new tab; or `tresor_login` to see the link |
| Python on your machine (script, Jupyter, VS Code) | `ATTACH` - the browser opens; in a notebook, `tresor_login` in one cell and `ATTACH` in the next |
| DBeaver, DataGrip (JDBC) | `ATTACH` - the browser opens while the query waits; or log in once from the CLI, and the IDE's DuckDB attaches with no browser |
| A remote kernel (JupyterHub), SSH, a container | no browser there: `tresor_login(..., login := 'device')`, open its `url` on your machine and enter its `user_code` |

On a remote machine with no credential store, the login lives in the process: a restarted kernel logs
in again.

## Switching identity

```sql
FROM tresor_logoff('corp');                                       -- forgets, revokes, detaches corp
FROM tresor_login('tresor:secrets.corp.example', prompt := 'select_account');
ATTACH 'tresor:secrets.corp.example' AS corp;
```

Without `prompt`, the identity provider's browser session would log the same person in again.
`prompt := 'select_account'` asks it to pick the account (Microsoft Entra ID), and
`prompt := 'login'` to enter the credentials again (any provider).

An IDE that shows `corp` in its tree can keep the catalog: `tresor_logoff('corp', detach := false)`.
Nothing held for the previous login is served from then on, and its queries ask for a login
(`FROM tresor_login('corp')`). After `tresor_login`, the next query takes it up - waiting for it while
it is in progress. Everything held for the previous login goes first: the list of secrets, the
material, the variables. The audit records a `login` with detail `resumed`, or `resumed_other` for
another person. `tresor_logoff('corp')` detaches a kept catalog that is still logged off.

The connection's default database (after `USE corp`) is not detached by `tresor_logoff`: DuckDB
refuses that. It stays, logged off, as with `detach := false`.

## The credential store on macOS

macOS keeps the login in the login keychain, readable by the program that stored it. Another program
reading it for the first time - Python, a JVM after the CLI - makes macOS ask you once to allow it.
Choose **Always Allow**. A new build of that program may ask again. Windows' Credential Manager and the
Secret Service on Linux do not ask.

## Pipelines are not people

A scheduled job does not log in as a person: it has a service identity of its own, a `tresor` secret
([Pipelines](./pipelines.md)).
