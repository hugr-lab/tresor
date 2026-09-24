# Spec 013: a service logs in without a shared secret — private_key_jwt, federated assertions, Azure managed identity; Auth0's audience; Entra checked live

- **Status**: implemented (Entra live: by hand, pending the owner's run)
- **Date**: 2026-09-24
- **Author**: VGSML (with Claude)

## Summary

A DuckDB node (a duckdb-acl server, a pipeline, a job) logs in to the secrets service as itself.
Today that means a `tresor` secret with `FLOW 'client_credentials'` and a `CLIENT_SECRET`: a shared
secret, written into the node's configuration and rotated by hand. This spec adds the ways a
production service is expected to prove itself instead, all built on duckdb-ext-common spec 012:

| `FLOW` | The service proves itself with | Typical host |
| --- | --- | --- |
| `client_credentials` + `PRIVATE_KEY_FILE` (private_key_jwt) | its own key; the IdP holds the public key or certificate | any server; Entra, Keycloak, Okta |
| `federated` | a token its platform issued: a Kubernetes service-account token file, or the GitHub Actions OIDC token | Kubernetes (Azure workload identity, Keycloak federated auth), CI |
| `managed_identity` | nothing: the Azure platform's endpoint hands out a token for the service | Azure VM, App Service, Functions, Container Apps |

On top of that:
- the discovery can ask clients to send the `audience` parameter (Auth0);
- a person's login and the node flows are checked live against the owner's Entra ID tenant.

## Problem

- **A node's `CLIENT_SECRET` is a long-lived shared secret.** It sits in a `tresor` secret, which a
  persistent DuckDB secret writes to a file. Anyone who reads it is the node until someone rotates
  it by hand. Every serious IdP offers better:
  - certificates or keys (private_key_jwt);
  - federation with the platform the node runs on (Kubernetes, GitHub);
  - on Azure, a platform identity with no credential at all.
- **Auth0 picks the access token's audience from an `audience` request parameter,** not from a
  scope. The protocol page says clients never send one, so a service behind Auth0 cannot get tokens
  meant for it today.
- **Entra is only unit-tested.** The claims shape, the v1/v2 issuers and On-Behalf-Of are covered by
  unit tests alone. The owner has a tenant.

## Design

### The `tresor` secret

```sql
-- private_key_jwt: the key stays in a file the operator manages (a mounted Kubernetes secret, a vault agent)
CREATE SECRET node (TYPE tresor, FLOW 'client_credentials', ISSUER 'https://login.microsoftonline.com/<t>/v2.0',
                    CLIENT_ID 'acl-node', PRIVATE_KEY_FILE '/var/run/secrets/node/key.pem',
                    CERTIFICATE_FILE '/var/run/secrets/node/cert.pem');       -- Entra: the certificate's thumbprint

-- federated: a token the platform put in a file (Kubernetes projected service-account token; Azure workload
-- identity sets AZURE_FEDERATED_TOKEN_FILE), re-read at every login
CREATE SECRET node (TYPE tresor, FLOW 'federated', ISSUER '...', CLIENT_ID 'acl-node',
                    ASSERTION_FILE '/var/run/secrets/azure/tokens/azure-identity-token');
-- ... or GitHub Actions' OIDC token, for the audience the IdP's federation expects
CREATE SECRET ci (TYPE tresor, FLOW 'federated', ISSUER '...', CLIENT_ID 'ci', ASSERTION_SOURCE 'github_actions',
                  ASSERTION_AUDIENCE 'api://AzureADTokenExchange');

-- Azure managed identity: nothing secret at all; CLIENT_ID for a user-assigned identity
CREATE SECRET node (TYPE tresor, FLOW 'managed_identity', ISSUER 'https://login.microsoftonline.com/<t>/v2.0',
                    CLIENT_ID '<user-assigned identity client id>');
```

- **Which parameters each flow takes.** A flow refuses the others' parameters, as today.
  - `client_credentials` takes a `CLIENT_SECRET` or a `PRIVATE_KEY_FILE`, never both.
  - `federated` takes an `ASSERTION_FILE` or an `ASSERTION_SOURCE`.
  - `managed_identity` takes no credential.
- **Only files, read at the moment of use.**
  - A key or a token is read when the login needs it: at ATTACH, and at every re-mint when the
    token runs out. It is used and wiped, so a rotated file is picked up.
  - The secret itself holds only paths. A persistent `tresor` secret therefore writes nothing secret
    to disk, unlike a `CLIENT_SECRET`.
  - A **key** file follows the SSH rule, as Kubernetes allows it, on POSIX systems. Others may not
    read it, and a group may only read it (a pod's `fsGroup` makes a secret volume 0440). Anything
    else is refused, and the reason says so. The check is on the opened descriptor (`fstat`).
  - Every file is subject to DuckDB's own sandbox (`enable_external_access`, `allowed_directories`),
    checked at each ATTACH. A file is at most 64 KiB.
  - A federated token file must hold a JWT's shape. A key or a config file is never sent as an
    assertion.
  - A federated **token** file is not held to that rule. Platforms mount it readable (Kubernetes
    projected tokens are 0644 by default), and it is short-lived and bound to an audience.
- **The key.** A PEM file: RSA (RS256) or P-256 (ES256).
  - `KEY_ID` sets the header's `kid` (Keycloak, Okta match on it).
  - `CERTIFICATE_FILE` adds `x5t` and `x5t#S256` (Entra matches on the certificate thumbprint).
- **What a managed identity's token is for.** The secret's required `AUDIENCE`, as the resource. The
  service's discovery must name the same audience, or the ATTACH is refused; the service never picks
  which Azure resource the identity mints for. The token then goes to the service like a `token` login's, but it is re-minted from
  the platform when it runs out. Such a login cannot act for sessions: there is no client to
  exchange tokens with (below).

### Acting for sessions (specs/008)

- `ACT_FOR_SESSIONS` needs a confidential client at the IdP, to exchange tokens as. Now any of
  `client_credentials` (secret or key) and `federated` is one: token exchange and Entra
  On-Behalf-Of accept the client assertion (ext-common 012).
- `managed_identity` is refused for `ACT_FOR_SESSIONS`, with the reason. Entra allows OBO with a
  managed identity only through a federated credential on an app registration, which is the
  `federated` flow with `ASSERTION_SOURCE 'azure_managed_identity'`. That is a follow-up, if the
  owner wants it.

### The discovery's `service_flows`

- The protocol already names `private_key_jwt` and `federated`; this spec adds `managed_identity`.
- A client uses only a flow its issuer lists, when the issuer lists any, as today.
- The reference server lists what its config allows. It verifies nothing of how the client got its
  token: the IdP did that.

### The audience parameter (protocol change)

- **The field.** An issuer in the discovery may say `"audience_parameter": true`.
- **What a client then sends.** `audience=<audience>` on the authorization request, the device
  request and the client credentials request.
- **Where it applies.** Only Auth0-style IdPs need it. Absent or false means the rule stays as
  today: the IdP's configuration puts the audience into tokens, and clients send nothing.
- **In the protocol page:** `website/docs/protocol.md` (Discovery) gains the field.

### Entra, checked live

`scripts/dev/entra_live.sh` runs against the owner's tenant, from environment variables only. The
tenant id, the app registrations and the certificate paths never go into the repository.
- It runs the reference server with the tenant's v2 issuer. `audience` is the API app's client id: a
  v2 token's `aud` is that id, not the Application ID URI. The URI builds the scopes.
- A person's login stays in memory (`TRESOR_KEYCHAIN=memory`).

1. **A person's login.** The browser, v2 tokens, the `aud` of the service's app ID URI, and
   remembered (specs/012).
2. **A service with a certificate** (private_key_jwt): a login, then `whoami`.
3. **A service with a secret:** the same, as a baseline.
4. **The node acting for alice** (On-Behalf-Of with the certificate): not in the script yet.
   - It needs a user token issued for the node's app, and duckdb-acl beside it.
   - The core path is tested: token exchange signed with a key (ext-common 012, and
     `service_identities.test` through acl_stub).
5. **Managed identity:** only where it runs on Azure. That is a later run on an Azure VM.

It prints what each step saw (flows, `aud`, `iss` version), never a token. The Entra setup it
expects (apps, API permissions, `accessTokenAcceptedVersion`) is documented in
`reference-server.md`.

## Enforcement & security

- **Nothing secret is stored.** A `tresor` secret holds paths and ids only (in the new flows). Key
  and token bytes live in memory for one request, and are wiped.
- **Where a file may come from.** It must be private to the user (POSIX), and its content goes only
  to the issuer's token endpoint (ext-common 012):
  - a key signs an assertion whose audience is that endpoint;
  - a federated token is presented there.
- **Where the platform endpoints may be.** IMDS is link-local plain http, and `IDENTITY_ENDPOINT` is
  honoured on loopback only (ext-common 012). A managed-identity token goes to the service only if
  its `aud` is the discovery's audience, the same check the node's exchange makes.
- **Unchanged:** a service's login is never remembered (specs/012), and nothing of it goes to disk.

## Testing

- **Fake IdP (test/fake).** A client-assertion check (the signature against a key the test
  generates, `aud`, `exp`, `jti` replay), a fake IMDS and App Service endpoint, and a fake GitHub
  token source.
- **sqllogictests:**
  - each flow's parameters, and the refusals: both a secret and a key, a group-readable key file, a
    missing file, `managed_identity` with `ACT_FOR_SESSIONS`;
  - a login and `whoami` per flow;
  - a re-mint picking up a rotated token file;
  - acting for a session with a key;
  - `audience_parameter` sent in each request.
- **Keycloak (CI):**
  - a client with a registered public key (private_key_jwt with `kid`);
  - "federated client authentication" with a Kubernetes-style token signed by a test issuer the
    realm trusts, if the pinned Keycloak supports it (26.2+). Otherwise it is skipped, and the spec
    says so.
- **Entra:** `entra_live.sh`, by hand, against the owner's tenant.

## The review's findings (applied)

- **HIGH: the credential files were read around DuckDB's sandbox.** With
  `enable_external_access = false`, `read_text()` was refused while a federated login still read the
  file and sent its content to the secret's issuer (confirmed). Now:
  - the sandbox applies to every file a login reads;
  - a federated token file must be JWT-shaped;
  - a file is at most 64 KiB.
- **HIGH: a managed identity's token was for whatever the discovery named.** A hostile service could
  name `https://management.azure.com/` and receive an ARM token; the `aud` check was circular. Now
  the secret names its `AUDIENCE`, and a discovery naming another is refused.
- **HIGH: `audience_parameter` defeated the node's exchange-audience guard (specs/008).** The node's
  own token carried the audience only because the discovery had asked for it. Now a node acting for
  sessions must pin `EXCHANGE_AUDIENCE` where the discovery sets `audience_parameter`.
- **Kubernetes' fsGroup was refused.** A group may now read a key (0440/0640), never write it. The
  check is on the opened file descriptor.
- **The exchange read files under the session's lock.** The credential (paths) is now copied under
  the lock and used outside it. The fallback exchange builds its proof afresh: a federated
  assertion may be single-use.
- **A key login read as `client_credentials`.** whoami and the audit now say `private_key_jwt`.
- **The managed identity's `aud` check failed open for a non-JWT token.** Now it fails closed.
- **The spec claimed tests that did not exist.** They exist now: renewal (a key, a federated file)
  through the `expiring` realm, a rotated token file picked up, the device request's audience, the
  header's `kid` and `x5t`, 0640 accepted.
- **Entra:**
  - the docs name the `idtyp` optional claim;
  - the redirect is `http://127.0.0.1/callback`;
  - the script fails when a step does, and cuts the node's secret out of its output.
- **Protocol:** `audience_parameter` is documented as trust equal to `scopes`.

## Checked

- **`test/sql/attach/service_identities.test`** (fake IdP, 109 assertions). The keys are made per run
  by `test_attach.sh`, and the fake verifies each signature with `openssl`.
  - Each flow's parameters and their refusals.
  - RSA and P-256 keys; `KEY_ID` with a certificate.
  - A group-readable key, a missing key, another client's key, a service that lists no service
    flows.
  - Federated: a token file, and GitHub Actions' token for the asked audience.
  - Managed identity: through the App Service endpoint, for the discovery's audience.
    - A token for another audience is not sent.
    - `ACT_FOR_SESSIONS` with it is refused.
  - Acting for an acl session with a key.
  - Auth0's `audience_parameter` on the client credentials and authorization requests, and absent
    elsewhere.
- **Keycloak** (`test_keycloak.sh`, CI). The run makes a key and a certificate and registers the
  certificate on the realm's `keynode` client (`client-jwt`) through the admin API. A DuckDB process
  then logs in with `PRIVATE_KEY_FILE`: the verified-live private_key_jwt.
- **Go:** the reference server's discovery carries `audience_parameter` only when configured.

## Follow-ups

- `ASSERTION_SOURCE 'azure_managed_identity'`: a managed identity as the federated credential of an
  app registration, so an Azure node without a secret can act for sessions.
- mssql-extension adopts ext-common 012 for its `managed_identity` provider.
- AWS (IAM Roles Anywhere, Cognito) and GCP (workload identity federation) as sources.
