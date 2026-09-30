---
sidebar_position: 3.5
title: Microsoft Entra ID
---

# Microsoft Entra ID

This page sets up a secrets service behind Entra ID (Azure AD):
- people log in from DuckDB with their Entra account;
- services and duckdb-acl nodes log in as themselves, with a certificate, a federated
  credential or a managed identity;
- a node acts for its users (On-Behalf-Of).

It uses the [reference server](./reference-server.md) as the service. A service of your own reads
the same tokens.

You register up to three applications in your tenant:

| Application | Who uses it | Kind |
| --- | --- | --- |
| **The service's API** (`duckdb-secrets`) | the secrets service | an API: the audience of every token the service accepts |
| **People's client** (`duckdb`) | people, from DuckDB | a public client (no secret) |
| **A node** (`acl-node`, `etl`, …) | a server, a pipeline, a job | a confidential client (a certificate, a federated credential, or a secret) |

A managed identity (Azure VMs, App Service, Functions, Container Apps) needs no application of its
own: it is given a role on the API.

:::note
Checked live against an Entra tenant on 2026-09-30 (`scripts/dev/entra_live.sh`, below):
- a person's browser login, through the `http://127.0.0.1/callback` redirect, any port;
- a node with its certificate (`private_key_jwt`), and with a client secret;
- v2 tokens throughout, the `idtyp` rule telling the node from the person, and the node's app role
  (`role:nodes`);
- a person holding `secrets_admin` and `analysts` as app roles, without duckdb-acl: creating a
  secret, granting `use` to `role:analysts` and `role:nodes`, DuckDB's lookup finding it only once
  granted, and no longer once revoked; the node finding the secret granted to its role.

Not yet checked live: On-Behalf-Of for a duckdb-acl node, a federated credential, and a managed
identity (it needs an Azure host). They are tested against the fake service and Keycloak, in CI.
:::

## 1. The service's API

**Entra admin center → App registrations → New registration.** Give it a name
(`duckdb-secrets`), accounts in this organizational directory only, and no redirect URI.

| Setting | Where | Value |
| --- | --- | --- |
| Application ID URI | Expose an API | `api://duckdb-secrets` (or the suggested `api://<client id>`) |
| A delegated scope | Expose an API → Add a scope | `access_as_user`, who can consent: admins and users |
| App roles | App roles | `secrets_admin`, `analysts` (allowed member types: users/groups); `nodes` (applications) |
| Token version 2 | Manifest | `"api": {"requestedAccessTokenVersion": 2}` (in the older manifest view: `"accessTokenAcceptedVersion": 2`) |
| Who may get tokens | Enterprise applications → duckdb-secrets → Properties | **Assignment required? Yes** (recommended) |
| The `idtyp` claim | Token configuration → Add optional claim → Access | `idtyp` |
| Groups (optional) | Token configuration → Add groups claim | security groups, emitted as group object ids |

Why each matters:
- **Version 2.** A v2 access token's `aud` is the API's **client id** (a GUID), and its `iss` is
  `https://login.microsoftonline.com/<tenant>/v2.0`. Without version 2, Entra issues v1 tokens:
  `iss` `https://sts.windows.net/<tenant>/`, and `aud` whatever was asked for (typically the
  Application ID URI). The service would refuse them as coming from another issuer.
- **`idtyp`.** The claim says `app` in a token an application got for itself. It is how the
  service tells a node's token from a person's (the `service` rule below). Without it, every node
  would be taken for a person.
- **App roles.** They become the principals the service knows:
  - `role:secrets_admin`: the administrators, in the service's policy (step 5);
  - `role:analysts`, `role:nodes`: what an administrator grants `use` to. Add a role per group of
    people that uses different secrets.
  - An administrator's role gives no `use` by itself. An administrator who is to use a secret also
    holds a role it is granted to.
  - People get roles under **Enterprise applications → duckdb-secrets → Users and groups**. Groups
    need Entra ID P1 or P2: the free tier assigns users only.
  - Applications get roles as an API permission (step 3).
- **One role per assignment.** The portal's *Add user/group* takes a single role: a person with
  two roles is assigned twice. When the portal offers no role to pick, Microsoft Graph does it
  (`az login --tenant <tenant id>` as an administrator of the tenant):

  ```sh
  api_sp=$(az ad sp list --filter "appId eq '<API client id>'" --query '[0].id' -o tsv)
  role=$(az ad sp show --id "$api_sp" --query "appRoles[?value=='analysts'].id | [0]" -o tsv)
  user=$(az ad user show --id <user principal name> --query id -o tsv)
  az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$api_sp/appRoleAssignedTo" \
    --headers Content-Type=application/json \
    --body "{\"principalId\":\"$user\",\"resourceId\":\"$api_sp\",\"appRoleId\":\"$role\"}"
  ```

- **A new role** shows in the next token: DETACH and ATTACH again (a remembered login is
  refreshed then). If it is still missing, `CALL tresor_logoff()` and ATTACH: that logs in through
  the browser.
- **Assignment required.** Without it, any user and any application in the tenant can get a token
  for the API. It has no roles, but it still is a `subject:` (or a `client:`) the service knows.
  Turn it on, or at least grant only to roles and groups.
- **Groups.** A group claim becomes `group:<object id>`. Entra leaves the claim out for a user in
  more than 200 groups (the overage): grant through app roles where that can happen.

Note the API's **client id**: it is the service's `audience`, and a managed identity's `AUDIENCE`.

## 2. People's client

**New registration** `duckdb`, no redirect URI yet. Then:

| Setting | Where | Value |
| --- | --- | --- |
| Redirect URI | Authentication → Add a platform → **Mobile and desktop applications** | `http://127.0.0.1/callback` |
| Public client flows | Authentication → Advanced settings | **Allow public client flows: Yes** (the device code flow) |
| API permission | API permissions → Add a permission → **APIs my organization uses** → `duckdb-secrets` → Delegated | `access_as_user` |
| Consent | API permissions | **Grant admin consent** (or let users consent) |

- tresor listens on `http://127.0.0.1:<a free port>/callback` for the browser's answer. Entra
  ignores the port of a loopback redirect URI but matches the host and the path (case-sensitive),
  so register exactly `http://127.0.0.1/callback`. Without it, the browser shows `AADSTS50011`.
- If the portal refuses `http://127.0.0.1/…`, add it in the **Manifest**: under
  `publicClient.redirectUris` (older view: `replyUrlsWithType` with `"type": "InstalledClient"`).
- `http://localhost/callback` is not the same URI to Entra; tresor sends the `127.0.0.1` literal.
- A tenant's Conditional Access may block the device code flow ("Authentication flows"). Then
  `LOGIN 'device'` fails with `AADSTS53003`, while the browser login works.
- The client has no secret: it is a public client with PKCE, as every DuckDB on a laptop is.
- Note its **client id**: it is the discovery's `client_id`.

## 3. A node

**New registration** (`acl-node`, `etl`, …). It proves itself in one of three ways. They are listed
from best to last resort.

**A federated credential**, when the node runs where a platform issues it a token. Go to
Certificates & secrets → Federated credentials → Add credential:
- **Kubernetes** (Azure workload identity, or any cluster whose OIDC issuer Entra can reach):
  - issuer: the cluster's OIDC issuer URL;
  - subject: `system:serviceaccount:<namespace>:<service account>`;
  - audience: `api://AzureADTokenExchange`.
  - With Azure workload identity, the pod carries the label `azure.workload.identity/use: "true"`,
    and the token is mounted at `/var/run/secrets/azure/tokens/azure-identity-token`.
  - The cluster's OIDC issuer and its keys must be reachable from Entra.
- **GitHub Actions:**
  - organization, repository and entity. The issuer is
    `https://token.actions.githubusercontent.com`, and the subject is one of:
    - `repo:<org>/<repo>:ref:refs/heads/<branch>`;
    - `…:environment:<name>`;
    - `…:ref:refs/tags/<tag>`;
    - `…:pull_request`.
  - audience: `api://AzureADTokenExchange`.

Nothing secret exists anywhere: the node presents the platform's token.

**A certificate** otherwise. Make a key and a certificate and upload the certificate under
Certificates & secrets → Certificates → Upload:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout node.key -out node.crt -days 365 -subj /CN=acl-node
chmod 600 node.key            # tresor refuses a key others may read (a group may read it: 640/440)
```

Entra matches the certificate by its thumbprint (`x5t#S256`, or the older SHA-1 `x5t`). tresor sends
both with each assertion, whose `aud` is the tenant's token endpoint. Use an RSA key: Entra's
certificate credentials are RSA. Keep `node.key` where only the node reads it: a mounted secret, a
vault agent.

**A client secret** only when neither of the above is possible. It is a shared secret: it lives in
the node's configuration and is rotated by hand.

Then give the node its role on the API:

| Setting | Where | Value |
| --- | --- | --- |
| API permission | API permissions → Add a permission → **APIs my organization uses** → `duckdb-secrets` → **Application permissions** | `nodes` |
| Consent | API permissions | **Grant admin consent** |

The API shows under **My APIs** only for its owners; **APIs my organization uses** finds it for
everyone (search by its name or client id). A new registration has only Graph's `User.Read`: the
API's permission is added by hand.

### A node acting for its users (duckdb-acl)

A duckdb-acl node serves people who reach it through quack or Flight SQL with their own Entra
tokens. For every session it trades the user's token for one meant for the service
(On-Behalf-Of). The service then answers as that user, through the node.

| Setting | Where | Value |
| --- | --- | --- |
| The node's own API | Expose an API | Application ID URI `api://acl-node`, a delegated scope (e.g. `sessions`) |
| Token version 2 | the node's Manifest | `"api": {"requestedAccessTokenVersion": 2}`: session tokens for the node are v2 |
| On-Behalf-Of | API permissions → Add a permission → **APIs my organization uses** → `duckdb-secrets` → **Delegated** | `access_as_user`, with admin consent |
| The client people reach the node with | its API permissions | the node's `sessions` scope |

- Users' tokens arrive at the node with `aud` = the node's client id. duckdb-acl's issuer is set up
  with that audience (`acl_define_issuer`).
- They must be v2 tokens: the node's API needs version 2 too. A v1 session token is refused as
  `this acl session's token is from another issuer than <host>'s login`.
- Only a user's token (delegated, with `scp`) can be exchanged; an application's cannot.
- Instead of admin consent, the node's manifest can list the client people use in
  `knownClientApplications`: users then consent to both in one prompt.
- **Conditional Access.** Policies on `duckdb-secrets` (MFA, a compliant device) that the user's
  sign-in did not satisfy make On-Behalf-Of fail with `interaction_required` (`AADSTS50076`,
  `AADSTS50079`), and the node cannot prompt anyone. Apply the same policies to the node's API, so
  that they are met when the user signs in.
- A node that logs in with a **managed identity** cannot act for users: it is no client that can
  exchange tokens. Use a federated credential or a certificate on an application. (A managed
  identity as the federated credential of the node's application would work in Entra; tresor has
  no assertion source for it yet.)

## 4. A managed identity

On an Azure VM, App Service, Functions or Container Apps, turn the identity on (system-assigned, or
attach a user-assigned one). Then give it the API's `nodes` role. The portal cannot assign app roles
to a managed identity; Microsoft Graph can:

```sh
api_sp=$(az ad sp list --filter "appId eq '<API client id>'" --query '[0].id' -o tsv)
role=$(az ad sp show --id "$api_sp" --query "appRoles[?value=='nodes'].id | [0]" -o tsv)
mi_sp=<the managed identity's object (principal) id>
az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$api_sp/appRoleAssignedTo" \
  --headers Content-Type=application/json \
  --body "{\"principalId\":\"$mi_sp\",\"resourceId\":\"$api_sp\",\"appRoleId\":\"$role\"}"
```

- The Graph call takes the identity's **object (principal) id**. The service, though, knows the
  identity by its **client (application) id**: the principal is `client:<client id>`.
- The platform caches the identity's tokens (up to about a day). A role assigned after a token was
  fetched shows only once the cache has expired or the host has restarted.

## 5. The service

The reference server's issuer entry for the tenant:

```yaml
issuers:
  - issuer: https://login.microsoftonline.com/<tenant id>/v2.0
    audience: <the API's client id>             # a v2 token's aud
    client_id: <people's client id>
    scopes: [openid, offline_access, api://duckdb-secrets/access_as_user]
    human_flows: [authorization_code, device_code]
    # token_exchange here: a node acting for its users (delegation grants)
    service_flows: [client_credentials, private_key_jwt, federated, managed_identity, token_exchange]
    roles_claim: roles
    groups_claim: groups
    service: {claim: idtyp, equals: app, client_claim: azp}   # a node's token, and its client id
policy:
  admins: [role:secrets_admin]
  actors:                                       # nodes that act for their users
    - {principal: "client:<acl-node's client id>", verbs: [use]}
```

- **Who is who:**
  - a person is `subject:<issuer>|<sub>`. Entra's `sub` is pairwise: stable for one person and this
    API, and different for every other application. A person should be the same `subject:` whether
    they log in directly or reach the service through a node (On-Behalf-Of), since both tokens are
    for `duckdb-secrets`; this is not yet checked live;
  - a node is `client:<its client id>`, and has `role:nodes` from its app role.
- **One tenant per issuer entry.** The server matches `iss` exactly. A multi-tenant API needs an
  entry per tenant; `/common` and `/organizations` are never an issuer.
- **Secrets that carry the caller's own token** (`token_exchange`,
  [concepts](./concepts.md#a-token-for-the-caller)) do not work with Entra in the reference server
  yet. It mints them with RFC 8693 token exchange; Entra's equivalent is On-Behalf-Of.

## 6. DuckDB

A person:

```sql
ATTACH 'tresor:secrets.corp.example' AS corp;     -- the browser; LOGIN 'device' over SSH
FROM corp.whoami();
```

An administrator (`role:secrets_admin`) keeps a secret in the service and grants its use:

```sql
CREATE PERSISTENT SECRET lake IN corp (TYPE s3, KEY_ID '…', SECRET '…', SCOPE 's3://lake');
CALL corp.grant_secret('lake', 'role:analysts', ['use']);
CALL corp.grant_secret('lake', 'role:nodes', ['use']);
FROM corp.grants('lake');
CALL corp.revoke_secret('lake', 'role:analysts');
```

A node, whichever way it proves itself. For `client_credentials` and `federated`,
`OAUTH_SCOPE 'api://…/.default'` is **required** with Entra: without it, tresor asks for the
discovery's scopes, and client credentials accept only `/.default` (`AADSTS1002012`). A managed
identity takes no `OAUTH_SCOPE`: it names `AUDIENCE` instead.

```sql
-- a federated credential (Kubernetes with Azure workload identity mounts the token here)
CREATE SECRET node (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'federated',
    CLIENT_ID '<node client id>', ISSUER 'https://login.microsoftonline.com/<tenant id>/v2.0',
    OAUTH_SCOPE 'api://duckdb-secrets/.default',
    ASSERTION_FILE '/var/run/secrets/azure/tokens/azure-identity-token');

-- GitHub Actions (permissions: id-token: write)
CREATE SECRET node (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'federated',
    CLIENT_ID '<node client id>', ISSUER 'https://login.microsoftonline.com/<tenant id>/v2.0',
    OAUTH_SCOPE 'api://duckdb-secrets/.default',
    ASSERTION_SOURCE 'github_actions', ASSERTION_AUDIENCE 'api://AzureADTokenExchange');

-- a certificate
CREATE SECRET node (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'client_credentials',
    CLIENT_ID '<node client id>', ISSUER 'https://login.microsoftonline.com/<tenant id>/v2.0',
    OAUTH_SCOPE 'api://duckdb-secrets/.default',
    PRIVATE_KEY_FILE '/etc/tresor/node.key', CERTIFICATE_FILE '/etc/tresor/node.crt');

-- a managed identity: no credential; AUDIENCE is the API's client id
-- (add CLIENT_ID '<user-assigned identity client id>' for a user-assigned one)
CREATE SECRET node (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'managed_identity',
    ISSUER 'https://login.microsoftonline.com/<tenant id>/v2.0', AUDIENCE '<the API client id>');

ATTACH 'tresor:secrets.corp.example' AS corp;
```

A duckdb-acl node acting for its users:

```sql
ATTACH 'tresor:secrets.corp.example' AS corp (ACT_FOR_SESSIONS true,
    EXCHANGE 'on_behalf_of', EXCHANGE_SCOPE 'api://duckdb-secrets/.default');
```

## 7. Check it

`scripts/dev/entra_live.sh` runs the reference server against your tenant (administrators:
`role:secrets_admin`) and logs DuckDB in:
- as a person, in the browser, holding `secrets_admin` and `analysts`, without duckdb-acl:
  - creates `entra_live`, an `http` secret with a placeholder token;
  - DuckDB's lookup does not find it: an administrator's role gives no `use`;
  - grants `use` to `role:analysts` and `role:nodes`: the lookup finds it;
  - revokes it from `role:analysts`: the lookup no longer finds it;
- as the node with its certificate, which finds the secret granted to `role:nodes`;
- with its secret too, when given.

Each step checks its own output and the script exits nonzero when one fails.

It takes everything from the environment, and never writes a credential or prints a token. It
needs a release build of this repository (`build/release/duckdb` and the extension) and Go, for
the server. `ENTRA_SKIP_PERSON=1` skips the browser step (the nodes then only log in);
`ENTRA_ADMIN_ROLE`, `ENTRA_USE_ROLE` and `ENTRA_NODE_ROLE` name other roles than `secrets_admin`,
`analysts` and `nodes`.

```sh
export ENTRA_TENANT=<tenant id> ENTRA_API_CLIENT_ID=<API client id> ENTRA_API_URI=api://duckdb-secrets \
       ENTRA_PEOPLE_CLIENT_ID=<people's client id> ENTRA_NODE_CLIENT_ID=<node client id> \
       ENTRA_NODE_KEY_FILE=node.key ENTRA_NODE_CERT_FILE=node.crt   # ENTRA_NODE_SECRET optional
scripts/dev/entra_live.sh
```

## When something is refused

| What you see | Why | Fix |
| --- | --- | --- |
| `AADSTS50011` in the browser | the redirect URI does not match | register `http://127.0.0.1/callback` under *Mobile and desktop applications* on people's client |
| `AADSTS7000218` at a device login | public client flows are off | *Allow public client flows: Yes* |
| `AADSTS65001` | consent is missing | grant admin consent on the API permission |
| `AADSTS700027` with a certificate | Entra does not know the certificate | upload the `.crt` that belongs to the key, on the same registration |
| `AADSTS700213` / `AADSTS700211` / `AADSTS700212` / `AADSTS70021` with a federated credential | the subject / the issuer / the audience does not match, or no federated credential matches | compare the credential with the token's `sub`/`iss`/`aud`; the audience is `api://AzureADTokenExchange` |
| `AADSTS700024` with a federated credential | the platform's token is out of its validity (a stale file) | the platform rotates the file; check the mount |
| `AADSTS7000215` | the client secret is wrong or expired | a new secret, or better a certificate |
| `AADSTS1002012` | a client credentials scope that is not `/.default` | `OAUTH_SCOPE 'api://duckdb-secrets/.default'` |
| `AADSTS53003` at a device login | Conditional Access blocks the device code flow | the browser login, or an exception in the policy |
| `AADSTS50076` / `AADSTS50079` for a node acting for a user | Conditional Access the user's sign-in did not satisfy | the same policies on the node's API |
| the service answers 401, `aud [...] does not contain "<audience>"` | the server's `audience` is the Application ID URI; a v2 token's `aud` is the client id | the server's `audience` is the API's client id |
| the service answers 401, `issuer "https://sts.windows.net/<tenant>/" is not configured` | a v1 token: the API is not on token version 2 | token version 2 on the API (step 1) |
| a node acting for a user: `this acl session's token is from another issuer than …` | the user's session token is v1: the node's API is not on version 2 | token version 2 on the node's API |
| `AADSTS50105` at a person's login | *Assignment required* is on, and the person holds no role | assign the person (or a group) under Enterprise applications → duckdb-secrets → Users and groups |
| `AADSTS501051` at a node's login | *Assignment required* is on, and the node holds no role | the `nodes` application permission, with admin consent |
| a node is treated as a person (no `client:` principal) | no `idtyp` claim | add the optional claim `idtyp` to the API's access tokens |
| a managed identity: `names the audience '<client id>', but the managed identity's secret is for 'api://…'` | `AUDIENCE` is the Application ID URI | `AUDIENCE` is the API's client id, as the service's audience |
| a person's groups are missing | the groups overage (over 200 groups) | grant through app roles |
| an administrator does not find a secret they created | an administrator's role gives no `use` | grant `use` to a role the administrator holds |
| whoami lacks a role just assigned | the token was issued before the assignment | DETACH and ATTACH; if still missing, `CALL tresor_logoff()` |
| the portal offers no role to pick | *Add user/group* takes one role, and may offer only one | the Graph call under step 1 |
| a node has `client:…` but no `role:nodes` | the node's registration lacks the API's **application** permission (a new registration has only Graph's `User.Read`) | API permissions → Add → duckdb-secrets → **Application permissions** → `nodes`, then **Grant admin consent** |
