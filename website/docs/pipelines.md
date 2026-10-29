---
sidebar_position: 3.8
title: Pipelines
---

# Pipelines

An ETL job, a dbt run or a scheduled notebook reads through the same secrets service as a person,
but it is not a person. It logs in as a **service**, with a `tresor` secret, and an administrator
grants its role `use` on what it reads:

```sql
-- an administrator, once
CALL corp.grant_secret('lake', 'role:etl', ['use']);
```

The job then finds the secret in DuckDB's lookup like anyone else. Nobody's browser is involved,
and nothing in the job depends on a person still working there.

## Pick the way the job proves itself

Best first. Use the first row that fits where the job runs.

| Where it runs | Flow | Secret on the machine |
| --- | --- | --- |
| [Kubernetes](#kubernetes) (AKS, EKS, GKE, any) | `federated`, the projected service-account token (`ASSERTION_FILE`) | none |
| [GitHub Actions](#github-actions) | `federated`, `ASSERTION_SOURCE 'github_actions'` | none |
| [A SPIFFE workload](#spiffe) (SPIRE, any platform) | `federated`, `ASSERTION_SOURCE 'spiffe'`, the JWT-SVID's file | none |
| [Azure](#azure-managed-identity) (VM, App Service, Functions, Container Apps) | `managed_identity`, or `federated` through it | none |
| [A VM or a worker with no platform identity](#a-key-on-the-machine) | `client_credentials` with a private key (`private_key_jwt`) | a key file (`0600`) |
| [Last resort](#a-client-secret) | `client_credentials` with a client secret | a shared secret |
| [A token already held](#a-token-already-held) | `FLOW 'token'` | a token, which expires |

Each flow is tested against the fake service in CI, and a key login against Keycloak. Checked live
against Entra: a key, a client secret, GitHub Actions' token, a managed identity (on Azure Container
Apps), a managed identity as an app registration's federated credential, and an AKS pod's projected
token; a Kubernetes token with Keycloak on kind (specs/027).

Every recipe below has the same shape: a `tresor` secret whose `SCOPE` names the service, then
`ATTACH`. The ATTACH finds the secret by its scope; `ATTACH … (SECRET name)` names it instead.

- Every flow but `token` names its `ISSUER`. It binds the login to that identity provider: the
  service's discovery must list it, and never sends the credential anywhere else.
- Except for `CLIENT_SECRET` and `TOKEN`, the secret holds **paths**, never a key or a token. The
  files are read when a login needs them.
- The files are subject to DuckDB's sandbox: with `enable_external_access = false`, a login reads
  only files under `allowed_directories` / `allowed_paths`, and any other key, certificate or token
  file is refused at ATTACH.
- Keep the secret temporary (plain `CREATE SECRET`). A `PERSISTENT` one is written to DuckDB's secret
  directory, a `CLIENT_SECRET` or a `TOKEN` in it included.
- With Entra ID, `client_credentials` and `federated` need `OAUTH_SCOPE 'api://<the API>/.default'`
  ([Microsoft Entra ID](./entra.md#6-duckdb)). The recipes below show it where Entra is the issuer.

## Kubernetes

The cluster issues the pod a service-account token, and the identity provider trusts the cluster's
OIDC issuer for that service account. Nothing secret is stored anywhere.

Mount the token with the audience the identity provider's federation expects:
`api://AzureADTokenExchange` for Entra, the provider's own value otherwise.

```yaml
# the pod's spec (in a Job or a CronJob: spec.template.spec / spec.jobTemplate.spec.template.spec)
spec:
  serviceAccountName: etl
  containers:
    - name: job
      image: …
      volumeMounts:
        - name: tresor-token
          mountPath: /var/run/secrets/tresor
          readOnly: true
  volumes:
    - name: tresor-token
      projected:
        sources:
          - serviceAccountToken:
              path: token
              audience: api://AzureADTokenExchange
              expirationSeconds: 3600
```

```sql
CREATE SECRET etl (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'federated',
    CLIENT_ID '<the job client id>', ISSUER 'https://login.microsoftonline.com/<tenant id>/v2.0',
    OAUTH_SCOPE 'api://duckdb-secrets/.default',
    ASSERTION_FILE '/var/run/secrets/tresor/token');
ATTACH 'tresor:secrets.corp.example' AS corp;
```

- The kubelet rotates the file before the token expires. tresor reads it again at every login and
  renewal, so a job longer than the token's life keeps working.
- The file must hold a JWT. Any other content is never sent.
- On AKS with Azure workload identity, the webhook mounts the token for you (pod label
  `azure.workload.identity/use: "true"`): `ASSERTION_FILE '/var/run/secrets/azure/tokens/azure-identity-token'`.
- The identity provider's side: a federated credential on the job's client with the cluster's
  issuer and the subject `system:serviceaccount:<namespace>:<service account>`
  ([Entra](./entra.md#3-a-node)). The cluster's OIDC issuer and its keys must be reachable from the
  identity provider.

### With Keycloak

Keycloak authenticates a client with a Kubernetes service-account token: a **Kubernetes identity
provider** trusts the cluster's issuer, and the client's authenticator is **Signed JWT -
Federated** (`federated-jwt`). Use **Keycloak 26.7 or later**. Both features
(`client-auth-federated`, `kubernetes-service-accounts`) are on by default since 26.6, but before
26.7 Keycloak requires a `client_id` parameter to equal the token's subject. tresor always sends
`CLIENT_ID`, so an older Keycloak refuses a client named anything else.

1. **Identity providers → Add provider → Kubernetes**. Set *Kubernetes Issuer URL* to the `iss`
   of the cluster's tokens, exactly. A cluster's internal issuer is
   `https://kubernetes.default.svc.cluster.local`, and Keycloak must then run in that cluster. A
   managed cluster's public OIDC issuer, such as AKS's
   `https://<region>.oic.prod-aks.azure.com/<tenant id>/<uuid>/`, works from anywhere. From 26.8,
   an *Issuer discovery URL* can be given instead, and Keycloak reads the issuer from it.
2. **The job's client**: a confidential client with service accounts. Under *Credentials*, set
   *Client Authenticator* to *Signed JWT - Federated*, *Identity provider* to the provider's
   alias, and *Federated subject* to `system:serviceaccount:<namespace>:<service account>`. Give
   it the audience mapper for the service, and give its service account the role the job uses.
   A realm created with the feature on already has *Signed JWT - Federated* in its client
   authentication flow. An older realm needs it added to a copy of the flow.
3. **The pod's token**: the audience is the realm's issuer URL, as Keycloak names itself
   (`https://<keycloak>/realms/<realm>`), and its only audience. By default Keycloak takes a
   Kubernetes token only within an hour of its issue time, so set `expirationSeconds` to 3600
   or less. The kubelet replaces the file well before then.

```sql
CREATE SECRET etl (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'federated',
    CLIENT_ID 'etl', ISSUER 'https://login.corp.example/realms/main',
    ASSERTION_FILE '/var/run/secrets/tresor/token');
ATTACH 'tresor:secrets.corp.example' AS corp;
```

Keycloak finds the client by the token's issuer and subject. tresor also sends `CLIENT_ID`, and
Keycloak refuses the login when the two do not name the same client. The test realm
`server/testdata/keycloak/realm-federated.json` is this setup, checked against Keycloak 26.8.1
in a kind cluster (`scripts/live/keycloak_kind.sh`).

## SPIFFE

A workload SPIRE attested logs in with its **JWT-SVID**. On a node with no platform identity, or across
platforms, that identity holds no secret and is rotated by the SPIRE agent. `spiffe-helper` keeps the SVID in
a file, with its audience the identity provider's (for Keycloak: the realm's issuer URL). tresor reads the file
at every login, so a rotated SVID is picked up.

`ASSERTION_SOURCE 'spiffe'` checks the SVID at every login before it is sent, and never sends one that fails a
check: its `sub` must be `SPIFFE_ID` (give it: a workload's file holds only its own SVID, but a misconfigured helper
should not log in as another workload), its `aud` must name the issuer (or `ASSERTION_AUDIENCE`), and it must not
have expired - "has expired - is spiffe-helper renewing it?" is the error when the helper stopped.

With **Keycloak's own SPIFFE support** (26.4 or later, a preview feature: start Keycloak with
`--features=spiffe`), the SVID is sent as `jwt-spiffe`, the only type Keycloak's SPIFFE authentication takes and
the source's default:

1. **Identity providers → Add provider → SPIFFE**: the *Trust domain* (`spiffe://corp.example`) and its
   *Bundle endpoint*, for example SPIRE's OIDC discovery provider's `/keys`.
2. **The workload's client**: a confidential client with service accounts, *Client Authenticator* *Signed JWT -
   Federated*, *Identity provider* the SPIFFE provider's alias, *Federated subject* the workload's SPIFFE ID.
   Give it the audience mapper for the service, and its service account the role the workload uses.
3. **SPIRE**: the SVID carries no `iss` (leave the server's `jwt_issuer` unset), as Keycloak's SPIFFE
   authentication expects.

```sql
CREATE SECRET node (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'federated',
    CLIENT_ID 'acl-node', ISSUER 'https://login.corp.example/realms/main',
    ASSERTION_SOURCE 'spiffe', ASSERTION_FILE '/run/spiffe/svid.jwt',
    SPIFFE_ID 'spiffe://corp.example/ns/data/sa/acl-node');
ATTACH 'tresor:secrets.corp.example' AS corp;
```

Keycloak refuses the same SVID as `jwt-bearer` (`invalid_client`). An identity provider that federates SPIRE as an
ordinary OIDC issuer (Entra, Okta, or Keycloak's OpenID Connect provider type) takes it as `jwt-bearer`: add
`ASSERTION_TYPE 'jwt-bearer'`, set SPIRE's `jwt_issuer`, and make its OIDC discovery reachable by the identity
provider (with Entra, `ASSERTION_AUDIENCE 'api://AzureADTokenExchange'`, the audience its federation expects).
Checked against Keycloak 26.8.1 and SPIRE 1.13.0 (`scripts/live/spiffe_keycloak.sh`, and the spike in
`examples/spiffe-spike`; specs/046).

## GitHub Actions

The workflow's own OIDC token is the job's credential. The job needs permission to ask for it:

```yaml
permissions:
  contents: read
  id-token: write
```

```sql
CREATE SECRET ci (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'federated',
    CLIENT_ID '<the job client id>', ISSUER 'https://login.microsoftonline.com/<tenant id>/v2.0',
    OAUTH_SCOPE 'api://duckdb-secrets/.default',
    ASSERTION_SOURCE 'github_actions', ASSERTION_AUDIENCE 'api://AzureADTokenExchange');
ATTACH 'tresor:secrets.corp.example' AS corp;
```

- `ASSERTION_AUDIENCE` is required: the audience the identity provider's federation expects.
- tresor asks GitHub for a fresh token at every login and renewal (`ACTIONS_ID_TOKEN_REQUEST_URL`
  and `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, which GitHub sets only with `id-token: write`).
- The federated credential names the workflow's subject, such as
  `repo:<org>/<repo>:environment:<name>`. A repository with GitHub's immutable subject claim
  presents `repo:<org>@<org id>/<repo>@<repo id>:…` instead
  ([Entra, step 3](./entra.md#3-a-node)). Bind it to an environment or a branch, not the whole
  repository.
- Checked live against Entra: `.github/workflows/entra-live.yml`.

## Azure managed identity

On an Azure VM, App Service, Functions or Container Apps, the platform's identity needs no
credential at all:

```sql
CREATE SECRET etl (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'managed_identity',
    ISSUER 'https://login.microsoftonline.com/<tenant id>/v2.0', AUDIENCE '<the API client id>');
    -- CLIENT_ID '<identity client id>' for a user-assigned identity
ATTACH 'tresor:secrets.corp.example' AS corp;
```

- `AUDIENCE` is what the token is for, and must be the service's audience (with Entra v2 tokens, the
  API's client id). A service whose discovery names another audience is refused, and a token the
  platform minted for another audience is never sent.
- The identity gets its role on the API through Microsoft Graph
  ([Entra, step 4](./entra.md#4-a-managed-identity)).
- On AKS, use workload identity ([Kubernetes](#kubernetes)) rather than the node's identity.
- **Through an app registration.** When the job must be a client at the identity provider (a
  duckdb-acl node acting for its users, or a registration that already holds the job's role), make
  the managed identity the registration's federated credential:

  ```sql
  CREATE SECRET etl (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'federated',
      CLIENT_ID '<the job client id>', ISSUER 'https://login.microsoftonline.com/<tenant id>/v2.0',
      OAUTH_SCOPE 'api://duckdb-secrets/.default',
      ASSERTION_SOURCE 'azure_managed_identity');   -- IDENTITY_CLIENT_ID '<…>' for a user-assigned one
  ```

  `ASSERTION_AUDIENCE` defaults to `api://AzureADTokenExchange`; set it in a sovereign cloud.

## A key on the machine

A VM, a bare-metal worker or an on-premises scheduler with no platform identity holds a private
key. The identity provider holds only the public half (a certificate, or a registered key), so
nothing shared can leak from the provider's side.

```sh
openssl req -x509 -newkey rsa:2048 -nodes -keyout etl.key -out etl.crt -days 365 -subj /CN=etl
chmod 600 etl.key
```

```sql
CREATE SECRET etl (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'client_credentials',
    CLIENT_ID 'etl', ISSUER 'https://login.corp.example/realms/main',
    PRIVATE_KEY_FILE '/etc/tresor/etl.key');
    -- KEY_ID 'k1' sets the assertion's kid; CERTIFICATE_FILE '/etc/tresor/etl.crt' adds its thumbprints (Entra)
ATTACH 'tresor:secrets.corp.example' AS corp;
```

- **File modes.** The key may be read by its owner and, read-only, by its group: `600`, `400`, `640`
  or `440`. tresor refuses a key others have any access to, or its group may write or execute. In
  Kubernetes, a Secret volume with `defaultMode: 0400` (a pod's `fsGroup` makes it 0440) passes; the
  default `0644` is refused. Windows has no such check: the file's ACL decides.
- Keys are RSA (2048 bits or more, RS256) or P-256 (ES256), unencrypted PEM. Entra's certificate
  credentials are RSA.
- The key and certificate are read again at every renewal: a rotated key is picked up.

## A client secret

Only when none of the above is possible. A client secret is a shared secret: it lives in the job's
configuration, it is rotated by hand, and anyone who copies it is the job.

```sql
CREATE SECRET etl (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'client_credentials',
    CLIENT_ID 'etl', CLIENT_SECRET '…', ISSUER 'https://login.corp.example/realms/main');
ATTACH 'tresor:secrets.corp.example' AS corp;
```

Bring the secret in from the scheduler's own secret store, and keep the `tresor` secret temporary.
`duckdb_secrets()` redacts `CLIENT_SECRET`.

## A token already held

When the job's runner already holds an access token for the service (another tool minted it), pass
it as it is:

```sql
CREATE SECRET etl (TYPE tresor, SCOPE 'tresor:secrets.corp.example', FLOW 'token', TOKEN '…');
ATTACH 'tresor:secrets.corp.example' AS corp;
```

It is never renewed. When it expires, or the service refuses it, calls fail with "the token of the
tresor secret for … has expired or was refused": replace the secret and ATTACH again. Use it for
short jobs. A token the runner renews is not picked up: each time, the job replaces the secret and
ATTACHes again.

## dbt

[dbt-duckdb](https://github.com/duckdb/dbt-duckdb)'s profile has the three pieces: `extensions`
loads tresor, `secrets` creates the `tresor` secret, `attach` attaches the service. dbt-duckdb runs
them in that order when it opens the database.

```yaml
lake:
  target: prod
  outputs:
    prod:
      type: duckdb
      path: /tmp/lake.duckdb
      extensions:
        - httpfs
        - name: tresor
          repo: community
      secrets:
        - type: tresor
          name: corp_login
          scope: tresor:secrets.corp.example
          flow: federated
          client_id: etl
          issuer: https://login.corp.example/realms/main
          assertion_file: /var/run/secrets/tresor/token
      attach:
        - path: tresor:secrets.corp.example
          alias: corp
          secret: corp_login
```

- dbt-duckdb turns this into `INSTALL tresor FROM community`, `LOAD tresor`,
  a temporary `CREATE OR REPLACE SECRET corp_login (type tresor, flow 'federated', …, scope
  'tresor:secrets.corp.example')` and `ATTACH IF NOT EXISTS 'tresor:secrets.corp.example' AS corp
  (SECRET corp_login)`.
- The secret must be created before the ATTACH, so tresor must be loaded by `extensions`: DuckDB
  knows the `tresor` secret type only once the extension is loaded.
- `alias` names the catalog (`AS corp`); without it DuckDB names the catalog after the path.
- tresor is built for DuckDB 2.0, and a loadable extension must match its host exactly: the `duckdb`
  Python package dbt-duckdb runs on must be the DuckDB 2.0 build tresor was built for.
- Any flow works the same way: its options are the secret's keys, in lower case. A client secret
  comes from the environment, never the file: `client_secret: "{{ env_var('ETL_CLIENT_SECRET') }}"`.
- tresor is a DuckDB community extension. Your organisation's own extension repository works the same way:
  `repo` is pasted as is, so a URL needs its own quotes - `repo: "'https://extensions.corp.example'"`.
- A build of your own is unsigned: `config_options: {allow_unsigned_extensions: true}`.
- Other ATTACH options go under the attachment's `options` (for example `insecure_http: true`
  against a local service).
- Models then read through DuckDB's lookup: `FROM 's3://lake/…'` finds the secret granted to the
  job's role. dbt's threads share the one DuckDB, so a run logs in once.

## Renewal

A service's login renews itself, and a long job does not fall off:
- the access token is renewed a minute before it expires (at half its life, for tokens that live two
  minutes or less), and again when the service answers 401;
- renewal is a new login from the secret: `client_credentials` mints again; a federated token file
  is read again (a rotated one included); GitHub Actions and a managed identity are asked again;
- a service's login is never remembered in the OS credential store: each process logs in from its
  secret;
- `FLOW 'token'` is the exception: it is never renewed.

## Many workers

Spark executors, Ray workers, parallel tasks of one job: each is its own process with its own
DuckDB, and **each logs in by itself**. Give them all the same `tresor` secret (the same key, or the
same mounted token). The identity provider sees one login per process, and one per renewal; the
service sees one principal, the job's client. Within one process, every connection to the DuckDB
uses its one login.

Hundreds of workers starting at once mean as many logins in a burst, and identity providers may
throttle token requests. Start workers in waves, or keep them long-lived.

## The identity provider's side

1. **A client for the job**, a confidential client with service accounts (client credentials), and
   the credential the recipe uses: a federated credential, a certificate or a registered key, or a
   secret.
   - Entra: [a node](./entra.md#3-a-node), and its application permission on the API.
   - Keycloak: a client with service accounts and an audience mapper for the service's audience
     ([reference server](./reference-server.md#identity-provider-setup-keycloak)); for a key, the
     client authenticator "Signed JWT" (`client-jwt`) with the job's certificate or key, as the test
     realm's `keynode` client (`server/testdata/keycloak/realm-tresor.json`). A key login against
     Keycloak is checked in CI. For a Kubernetes token, "Signed JWT - Federated"
     ([Kubernetes, with Keycloak](#with-keycloak)).
2. **A role on the API** for the client (an app role, a realm role), which the token carries. An
   administrator grants that role `use` on the secrets the job reads. Grants go to roles and groups,
   never to one client.
3. **The service tells a job from a person** by a claim (the reference server's `service` rule:
   `client_id` for Keycloak, `idtyp` for Entra), and gives it the principal `client:<client id>`
   (in whoami's `roles`).
4. **The service lists the flow** in its discovery's `service_flows`
   ([protocol](./protocol.md#discovery)). When the list is present, tresor attempts no flow outside
   it: a key login needs `private_key_jwt`, a federated one `federated`, a managed identity
   `managed_identity`, a client secret `client_credentials`.

```sql
FROM corp.whoami();   -- roles [role:etl, client:etl], login federated (or private_key_jwt, …)
```

## No person's login on a schedule

A scheduled job does not run "as the analyst". To do that, the job would need the person's refresh
token on a server: a long-lived credential of a person, outside the person's machine and its OS
credential store, used while nobody is there, and with everything the person may do. tresor does not
support it:
- a person's login is remembered only in that person's own OS credential store;
- a `tresor` secret describes a service's credential, never a person's;
- the job gets a service identity with a role, and an administrator grants the role what the job
  needs. What the job may read is then visible in the grants and does not change when people change
  teams.

`FLOW 'token'` takes any token. Handing it a person's token is still a person's login on a server,
and it ends when that token expires.

## Not yet

Recorded as candidates, each its own spec when asked for:
- **A `tresor` secret from environment variables**: an ATTACH with no SQL about the login, the
  flow and its options taken from the job's environment.
- **`ASSERTION_SOURCE 'gcp_metadata'`**: Google Compute Engine's identity token as the federated
  assertion. Today, on GKE use the [Kubernetes](#kubernetes) recipe.
