---
sidebar_position: 4
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
tresor's Entra support is tested against the protocol's shapes: v2 tokens, `x5t` certificate
matching, On-Behalf-Of, managed identity endpoints. The live run against a tenant is
`scripts/dev/entra_live.sh` (below). Until it has been run on yours, treat the steps here as the
design they are written from.
:::

## 1. The service's API

**Entra admin center → App registrations → New registration.** Give it a name
(`duckdb-secrets`), accounts in this organizational directory only, and no redirect URI.

| Setting | Where | Value |
| --- | --- | --- |
| Application ID URI | Expose an API | `api://duckdb-secrets` (or the suggested `api://<client id>`) |
| A delegated scope | Expose an API → Add a scope | `access_as_user`, who can consent: admins and users |
| App roles | App roles | `secrets_admin` (allowed member types: users/groups), `nodes` (applications) |
| Token version 2 | Manifest | `"requestedAccessTokenVersion": 2` (in the older manifest view: `"accessTokenAcceptedVersion": 2`) |
| The `idtyp` claim | Token configuration → Add optional claim → Access | `idtyp` |
| Groups (optional) | Token configuration → Add groups claim | security groups, emitted as group object ids |

Why each matters:
- **Version 2.** A v2 access token's `aud` is the API's **client id** (a GUID), and its `iss` is
  `https://login.microsoftonline.com/<tenant>/v2.0`. Without version 2, Entra issues v1 tokens:
  `iss` `https://sts.windows.net/<tenant>/`, and `aud` the Application ID URI. The service would
  refuse them as coming from another issuer.
- **`idtyp`.** The claim says `app` in a token an application got for itself. It is how the
  service tells a node's token from a person's (the `service` rule below). Without it, every node
  would be taken for a person.
- **App roles.** They become the principals the service grants to: `role:secrets_admin`,
  `role:nodes`. A role is assigned under **Enterprise applications → duckdb-secrets → Users and
  groups** for people and groups, and granted to applications as an API permission (step 3).
- **Groups.** A group claim becomes `group:<object id>`. Entra leaves the claim out for a user in
  more than 200 groups (the overage): grant through app roles where that can happen.

Note the API's **client id**: it is the service's `audience`, and a managed identity's `AUDIENCE`.

## 2. People's client

**New registration** `duckdb`, no redirect URI yet. Then:

| Setting | Where | Value |
| --- | --- | --- |
| Redirect URI | Authentication → Add a platform → **Mobile and desktop applications** | `http://127.0.0.1/callback` |
| Public client flows | Authentication → Advanced settings | **Allow public client flows: Yes** (the device code flow) |
| API permission | API permissions → My APIs → duckdb-secrets → Delegated | `access_as_user` |
| Consent | API permissions | **Grant admin consent** (or let users consent) |

- tresor listens on `http://127.0.0.1:<a free port>/callback` for the browser's answer. Entra
  ignores the port of a loopback redirect URI but matches the host and the path, so register
  exactly `http://127.0.0.1/callback`. Without it, the browser shows `AADSTS50011`.
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
- **GitHub Actions:**
  - organization, repository and entity (a branch, an environment, a tag);
  - audience: `api://AzureADTokenExchange`.

Nothing secret exists anywhere: the node presents the platform's token.

**A certificate** otherwise. Make a key and a certificate and upload the certificate under
Certificates & secrets → Certificates → Upload:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout node.key -out node.crt -days 365 -subj /CN=acl-node
chmod 600 node.key            # tresor refuses a key others may read
```

Entra matches the certificate by its thumbprint (`x5t`), which tresor sends with each signed
assertion. Keep `node.key` where only the node reads it: a mounted secret, a vault agent.

**A client secret** only when neither of the above is possible. It is a shared secret: it lives in
the node's configuration and is rotated by hand.

Then give the node its role on the API:

| Setting | Where | Value |
| --- | --- | --- |
| API permission | API permissions → My APIs → duckdb-secrets → **Application permissions** | `nodes` |
| Consent | API permissions | **Grant admin consent** |

### A node acting for its users (duckdb-acl)

A duckdb-acl node serves people who reach it through quack or Flight SQL with their own Entra
tokens. For every session it trades the user's token for one meant for the service
(On-Behalf-Of). The service then answers as that user, through the node.

| Setting | Where | Value |
| --- | --- | --- |
| The node's own API | Expose an API | Application ID URI `api://acl-node`, a delegated scope (e.g. `sessions`) |
| On-Behalf-Of | API permissions → duckdb-secrets → **Delegated** | `access_as_user`, with admin consent |
| The client people reach the node with | its API permissions | the node's `sessions` scope |

- Users' tokens arrive at the node with `aud` = the node's client id. duckdb-acl's issuer is set up
  with that audience (`acl_define_issuer`).
- They must be v2 tokens: the node's API needs version 2 too (step 1's manifest setting, on the
  node's registration). A v1 session token is refused as "from another issuer".
- A node that logs in with a **managed identity** cannot act for users: it is no client that can
  exchange tokens. Use a federated credential or a certificate on an application.

## 4. A managed identity

On an Azure VM, App Service, Functions or Container Apps, turn the identity on (system-assigned, or
attach a user-assigned one). Then give it the API's `nodes` role. The portal cannot assign app roles
to a managed identity; Microsoft Graph can:

```sh
api_sp=$(az ad sp list --filter "appId eq '<API client id>'" --query '[0].id' -o tsv)
role=$(az ad sp show --id "$api_sp" --query "appRoles[?value=='nodes'].id | [0]" -o tsv)
mi_sp=<the managed identity's object (principal) id>
az rest --method POST --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$mi_sp/appRoleAssignments" \
  --body "{\"principalId\":\"$mi_sp\",\"resourceId\":\"$api_sp\",\"appRoleId\":\"$role\"}"
```

## 5. The service

The reference server's issuer entry for the tenant:

```yaml
issuers:
  - issuer: https://login.microsoftonline.com/<tenant id>/v2.0
    audience: <the API's client id>             # a v2 token's aud
    client_id: <people's client id>
    scopes: [openid, offline_access, api://duckdb-secrets/access_as_user]
    human_flows: [authorization_code, device_code]
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
  - a person is `subject:<issuer>|<sub>`. Entra's v2 `sub` is pairwise: stable for one person and
    this API, and different for every other application;
  - a node is `client:<its client id>`, and has `role:nodes` from its app role.
- **Secrets that carry the caller's own token** (`token_exchange`,
  [concepts](./concepts.md#a-token-for-the-caller)) do not work with Entra in the reference server
  yet. It mints them with RFC 8693 token exchange; Entra's equivalent is On-Behalf-Of.

## 6. DuckDB

A person:

```sql
ATTACH 'tresor:secrets.corp.example' AS corp;     -- the browser; LOGIN 'device' over SSH
FROM corp.whoami();
```

A node, whichever way it proves itself (`OAUTH_SCOPE` asks Entra for the API's application
permissions):

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
CREATE SECRET node (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'managed_identity',
    ISSUER 'https://login.microsoftonline.com/<tenant id>/v2.0', AUDIENCE '<the API client id>');
    -- CLIENT_ID '<user-assigned identity client id>' for a user-assigned one

ATTACH 'tresor:secrets.corp.example' AS corp;
```

A duckdb-acl node acting for its users:

```sql
ATTACH 'tresor:secrets.corp.example' AS corp (ACT_FOR_SESSIONS true,
    EXCHANGE 'on_behalf_of', EXCHANGE_SCOPE 'api://duckdb-secrets/.default');
```

## 7. Check it

`scripts/dev/entra_live.sh` runs the reference server against your tenant and logs DuckDB in:
- as a person, in the browser;
- as the node with its certificate;
- with its secret too, when given.

It takes everything from the environment, and never writes a credential or prints a token:

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
| `AADSTS700213` / `AADSTS70021` with a federated credential | the subject, issuer or audience does not match the federated credential | compare the credential with the token's `sub`/`iss`/`aud`; the audience is `api://AzureADTokenExchange` |
| the service answers 401, "aud … does not contain" | a v1 token, or the audience configured as the URI | set the API's token version to 2; the server's `audience` is the API's client id |
| "from another issuer" / "issuer … is not configured" | a v1 token (`sts.windows.net`) | token version 2 on the API (and on the node's API, for On-Behalf-Of) |
| a node is treated as a person (no `client:` principal) | no `idtyp` claim | add the optional claim `idtyp` to the API's access tokens |
| a managed identity: "is not meant for" | `AUDIENCE` is the URI, the token's `aud` the client id | `AUDIENCE` is the API's client id |
| a person's groups are missing | the groups overage (over 200 groups) | grant through app roles |
