---
sidebar_position: 2
title: Getting started
---

# Getting started

:::caution Work in progress
Attaching, logging in, `corp.whoami()`, `corp.secrets()` and using the service's secrets work today.
*Store and manage* describes what comes next.
:::

## Install

```sql
INSTALL tresor;   -- from your organisation's extension repository, or community once published
```

No `LOAD` is needed: attaching a `tresor:` path loads the installed extension by itself.

## As a person: attach with a connection string

```sql
ATTACH 'tresor:secrets.corp.example' AS corp;
```

The service is named by host, optional port and base path — `tresor:host[:port][/base]` — and https
is implied. (Not a URL: given an `https://` path, DuckDB's ATTACH treats it as a remote database file,
requires httpfs and forces read-only before it ever looks at the type.)

tresor reads the service's discovery document (`/.well-known/duckdb-secrets`), learns which identity
provider to use, and logs you in:

- in a browser (authorization code + PKCE, redirected back to a local port), or
- with a device code, when there is no browser (SSH, containers) — the URL and code are printed.

`LOGIN 'auto'` (the default) opens a browser when it can: always on macOS and Windows, and on Linux
when a display is set. Otherwise it uses the device code. `LOGIN 'browser'` and `LOGIN 'device'`
choose explicitly. The environment variable `BROWSER` names the program to open the URL with. The
login waits up to `LOGIN_TIMEOUT` seconds (300 by default), and Ctrl-C cancels it.

If the service accepts more than one identity provider, name yours:

```sql
ATTACH 'tresor:secrets.corp.example' AS corp (ISSUER 'https://login.corp.example/realms/main');
```

The login lasts for the session and refreshes by itself. Access tokens stay in memory.

**One login, remembered.** Your refresh token is kept in the operating system's credential store: the
macOS Keychain, the Windows Credential Manager, or the Secret Service on Linux (GNOME Keyring,
KWallet). It is never kept in a file.
- The next ATTACH of the same service needs no browser, in this DuckDB process or a later one.
- A login is kept for the service it was made for. Another service behind the same identity provider
  gets a login of its own: one browser round, which takes a click while the provider's own session
  lives. A service never receives a token that was refreshed for another service.

```sql
ATTACH 'tresor:secrets.corp.example' AS corp;               -- the browser, once
-- ... a new DuckDB process, the next day:
ATTACH 'tresor:secrets.corp.example' AS corp;               -- no browser
CALL tresor_logoff();                                       -- forget it, revoke it at the IdP
```

- `REMEMBER false` on an ATTACH neither reads nor writes the store.
- `SET tresor_keychain = 'off'` turns remembering off for the whole instance; `'memory'` keeps it
  within this process.
- The environment variable `TRESOR_KEYCHAIN` sets the setting's default. Use `off` on a shared
  account such as a CI runner or a jump host.
- Where no store answers (a server, a container), the browser simply runs each time.
- `tresor_logoff()` forgets every remembered login attached here. `tresor_logoff('corp')` forgets
  one attachment's login. For a service that is not attached, name all three:
  `tresor_logoff(service := 'secrets.corp.example', issuer := '…', client_id := '…')`.
- Either way the login is revoked at the identity provider when it supports RFC 7009, and the
  attachment running on it must be attached again. A `REMEMBER false` attachment is not touched.
- **To log in as someone else**, call `tresor_logoff` first or attach with `REMEMBER false`. An
  explicit `LOGIN 'browser'` still uses the remembered login.
- `tresor_logoff` is refused for a statement run under a duckdb-acl session.

A service's login (a tresor secret) is never remembered: it logs in again from its secret.

```sql
FROM corp.whoami();      -- service, issuer, subject, roles, token expiry, what you may create, login flow
FROM corp.secrets();     -- the secrets you may see, with what you may do with each (no material)
```

The attached catalog `corp` holds functions only. It is read-only: you cannot create tables in it.

## As a service: attach with a secret

A process without a person logs in with its own credential, kept in a local secret of tresor's type:

```sql
CREATE SECRET corp_login (
    TYPE tresor,
    SCOPE 'tresor:secrets.corp.example',
    FLOW 'client_credentials', CLIENT_ID '…', CLIENT_SECRET '…',
    ISSUER 'https://login.corp.example/realms/main'   -- the IdP this credential belongs to
    -- optional: OAUTH_SCOPE 'api://duckdb-secrets/.default'
);
ATTACH 'tresor:secrets.corp.example' AS corp;                       -- the secret is found by its SCOPE
ATTACH 'tresor:secrets.corp.example' AS corp (SECRET corp_login);   -- or named
```

`SCOPE` is required and names the service: `tresor:<host>[:port][/base]`. It covers that host, any
path under it and, when it names no port, any port. A longer scope wins over a shorter one. A
`client_credentials` secret must name its `ISSUER`, so a service's credential only ever goes to its
own identity provider, whatever the secrets service's discovery says. `LOGIN 'browser'` or
`LOGIN 'device'` always logs you in as yourself, even when a service secret covers the host.

`FLOW 'token', TOKEN '…'` uses an access token the process already holds. It is not renewed: when it
expires, replace the secret and attach again.

**Without a shared secret.** A server should not carry a `CLIENT_SECRET`. These ways prove the
service to its identity provider instead:

```sql
-- its own key (private_key_jwt): the identity provider holds the public key or the certificate
CREATE SECRET node (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'client_credentials',
    CLIENT_ID 'acl-node', ISSUER 'https://login.microsoftonline.com/<tenant>/v2.0',
    PRIVATE_KEY_FILE '/var/run/secrets/node/key.pem',
    CERTIFICATE_FILE '/var/run/secrets/node/cert.pem');   -- Entra matches the certificate; KEY_ID for a kid

-- a token its platform issued (a Kubernetes service-account token, Azure workload identity)
CREATE SECRET node (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'federated',
    CLIENT_ID 'acl-node', ISSUER '…', ASSERTION_FILE '/var/run/secrets/azure/tokens/azure-identity-token');

-- in a GitHub Actions job (permissions: id-token: write)
CREATE SECRET ci (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'federated',
    CLIENT_ID 'ci', ISSUER '…', ASSERTION_SOURCE 'github_actions',
    ASSERTION_AUDIENCE 'api://AzureADTokenExchange');

-- on Azure: the platform's managed identity, nothing secret at all (CLIENT_ID for a user-assigned one);
-- AUDIENCE names what its token is for, and must be the service's audience
CREATE SECRET node (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'managed_identity',
    ISSUER 'https://login.microsoftonline.com/<tenant>/v2.0', AUDIENCE '<the service API app client id>');
```

- **The secret holds paths, never a key or a token.**
  - Files are read when a login needs them, at ATTACH and at each renewal, so rotated files are
    picked up.
  - A key file may be read by its owner and, read-only, by its group (`chmod 600` or `640`;
    Kubernetes: `defaultMode: 0400`, which a pod's `fsGroup` makes 0440). Others may not read it,
    and no group may write it. There is no check on Windows, where the file's ACL decides.
  - The files are subject to DuckDB's own sandbox: with `enable_external_access = false` (outside
    `allowed_directories`), a login reads none.
  - A federated token file must hold a JWT; any other content is never sent.
  - Keys are RSA (2048 bits or more, RS256) or P-256 (ES256), unencrypted PEM.
- **A node acting for duckdb-acl sessions** (`ACT_FOR_SESSIONS`) may log in with a key or
  federated. A managed identity cannot: it is no client at the identity provider, so it has
  nothing to exchange a session's token as.
- **A managed identity's token is only for `AUDIENCE`.** A service whose discovery names another
  audience is refused, and a token the platform minted for another audience is never sent.
- **An identity provider that takes the audience from a request parameter** (Auth0) gets it when
  the service's discovery sets `audience_parameter`. Nothing to configure on the client, except
  that a node acting for sessions then has to pin `EXCHANGE_AUDIENCE` itself.

A `PERSISTENT` secret is written to DuckDB's local secret directory like any other. A
`CLIENT_SECRET` in it is written too; the flows above write only paths and ids. Keep a secret's
credential in a temporary secret when the process can create it from its environment.

## Development against a local service

Plain http is allowed only to this machine, and only when asked for:

```sql
ATTACH 'tresor:127.0.0.1:8080' AS dev (INSECURE_HTTP true);
```

## Use the secrets

Secrets from the service take part in DuckDB's ordinary lookup, and nothing names tresor. The attach
registers a secret storage under the catalog's name (`corp`):
- It matches scopes like any storage: the longest scope wins, and on a tie a local secret wins.
- It fetches a secret's material only when a lookup picks it, and keeps it in memory only. A static
  secret is kept for up to 5 minutes or until its version changes. A dynamic one is kept until
  shortly before it expires.
- A secret you may see but not `use` never matches, and is not found by name either.
- `DETACH corp` takes the secrets out of the lookup. So does an ATTACH that is rolled back.
- The service's own secrets of type `tresor` (logins) are listed in `corp.secrets()`, but never take
  part in the lookup: a service cannot plant how you log in elsewhere.

```sql
ATTACH '' AS crm (TYPE mssql, SECRET crm_ro);
FROM 's3://lake/sales/*.parquet';
FROM which_secret('s3://lake/sales/x.parquet', 's3');   -- which secret, from which storage
```

**Dynamic secrets.** A dynamic `s3`, `r2` or `gcs` secret (short-lived credentials the service
mints) is refreshed when S3 turns its key away mid-query:
- httpfs's `REFRESH auto` goes through tresor's provider, which asks the service for a fresh one;
  nothing is written back.
- Refreshing needs `allow_persistent_secrets` (the DuckDB default), like every write to the service.
- A static service secret is never refreshed. If its key stops working, rotate it in the service.

`duckdb_secrets()` lists the service's secrets too, but without material.

If the service becomes unreachable, the last list it gave still decides what it covers:
- A lookup that one of its secrets would win fails with the service's name, rather than quietly going
  without a credential.
- Other paths, `duckdb_secrets()` and your local secrets keep working.

A local secret with the same name as one of the service's makes `SECRET name` ambiguous (DuckDB's
rule). Name it with the storage, or rename one of them.

## Store and manage (administrators)

Only administrators store secrets in the service and grant their use, to roles and groups; a user
keeps their own credentials in their own DuckDB.

```sql
CREATE PERSISTENT SECRET lake_rw IN corp (TYPE s3, KEY_ID '…', SECRET '…', SCOPE 's3://lake');
CREATE PERSISTENT SECRET IF NOT EXISTS lake_rw IN corp (…);     -- nothing if it exists
CREATE OR REPLACE PERSISTENT SECRET lake_rw IN corp (…);        -- replaces it
SET default_secret_storage = 'corp';                           -- PERSISTENT without IN goes to the service

CALL corp.annotate_secret('lake_rw', 'Read-write on the lake bucket, owned by the data team');
CALL corp.grant_secret('lake_rw', 'role:data_team', ['use']);   -- use, to a role or a group
FROM corp.grants('lake_rw');
CALL corp.revoke_secret('lake_rw', 'role:data_team');
DROP PERSISTENT SECRET lake_rw FROM corp;
```

A server acting for users (a duckdb-acl node) gets a role of its own; grant it what the server serves:

```sql
CALL corp.grant_secret('lake_rw', 'role:acl-nodes', ['use']);   -- the node serves it to its users
```

The service decides whether each of these is allowed, from your role. Some things to know:
- **Names.** DuckDB compares secret names case-insensitively. A new secret is stored in lower case,
  and an existing one is found by any spelling.
- **Resolved credentials.** A secret made with a resolving provider (for example s3's
  `credential_chain`) is stored with *your* resolved credentials, and whoever you grant it to
  receives them.
- **Writes take effect immediately.** A `ROLLBACK` does not undo a `CREATE … IN corp`: the service
  has no transaction to join.
- **Secret types need their extension.** The type must be one DuckDB knows (an `s3` secret needs
  httpfs loaded), as for any storage. `allow_persistent_secrets = false` refuses persistent writes,
  the service's included.
- **Name the storage when dropping.** `DROP SECRET name` without `FROM corp` finds the secret by
  name. By name tresor only finds secrets you may `use`, and it fetches the material, which the
  service may record as a use. `FROM corp` needs only `delete`.

## Detach

```sql
DETACH corp;   -- logs out: the tokens are dropped (and, once secrets arrive, they leave the lookup)
```
