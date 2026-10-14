# Spec 027: live checks of a pipeline's login - Kubernetes, Keycloak, Entra

- **Status**: accepted (Keycloak checked locally; the Azure checks pending)
- **Date**: 2026-10-14
- **Author**: hugr lab
- **Asked by**: the owner: prove the flows of `website/docs/pipelines.md` live, not only against the fake

## Summary

`website/docs/pipelines.md` (specs/026) recommends, best first, a Kubernetes service-account token, an Azure managed
identity and a managed identity as an app registration's federated credential. CI proves them against the fake
service. This spec checks them against the real identity providers: Entra on a temporary Azure stand (a Container
Apps job with a user-assigned identity, a one-node AKS with OIDC issuer and workload identity), and Keycloak's
federated client authentication with a Kubernetes token, locally on kind. No tresor code changes: the scripts,
an image to run them in, a test realm, and the docs' Keycloak setup.

## Design

### What is checked where

| # | Check | Flow | Where | Command |
| --- | --- | --- | --- | --- |
| 1 | an Azure managed identity logs in itself | `managed_identity` (`CLIENT_ID` = the user-assigned identity) | Azure: Container Apps job | `/live/check.sh mi` |
| 2 | an app registration (acl-node) with the identity's token as its federated assertion | `federated`, `ASSERTION_SOURCE 'azure_managed_identity'`, `IDENTITY_CLIENT_ID` | Azure: the same job | `/live/check.sh fed` |
| 3 | a pod's projected service-account token as the app registration's assertion (Entra) | `federated`, `ASSERTION_FILE` | Azure: AKS, ServiceAccount `tresor-logins/duckdb`, projected token mode 0440, audience `api://AzureADTokenExchange` | `/live/check.sh aks` |
| 4 | a Kubernetes token as a Keycloak client's assertion | `federated`, `ASSERTION_FILE` | local: kind + Keycloak 26.8.1 + ref-server (`scripts/live/keycloak_kind.sh`); optionally the stand's Keycloak in AKS | `/live/check.sh kc` |

A check passes when whoami says the expected `login` (`managed_identity` or `federated`) and the role
`role:nodes`, and fails with a nonzero exit otherwise.

### The scripts (`scripts/live/`)

- `check.sh mi|fed|aks|kc`: the stand's contract (POSIX sh). The service's https address in `TRESOR_URL` (the
  ATTACH path is `tresor:` plus the address without `https://`), `TRESOR_ISSUER`, `TRESOR_AUDIENCE`,
  `TRESOR_API_URI` (`OAUTH_SCOPE '<uri>/.default'`), `TRESOR_ACL_CLIENT_ID`, `TRESOR_MI_CLIENT_ID` (mi, fed),
  `TRESOR_ASSERTION_FILE` (aks, kc). Prints `login=… roles=…` and `listed=<n>` (the secrets the identity may see),
  masks anything shaped like a JWT.
- `<check>.sql` + `run.sh <check>`: the same flows as SQL scripts that take everything through `getenv()`
  (`managed_identity`, `mi_federated`, `k8s_entra`, `k8s_keycloak`), for a developer's build or the image
  (`TRESOR_DUCKDB`, `TRESOR_EXTENSION`). Each asserts in SQL (`error()`), prints `login=… subject=… roles=…`
  and `secrets=<names>`, and `run.sh` checks the lines, exits nonzero on a mismatch, and masks tokens and the
  platform's identity header. An `http://` `TRESOR_URL` (a local service) attaches with `INSECURE_HTTP`. The
  client principal `client:<id>` is accepted as whoami's subject (the fake, Entra) or in its roles (the
  reference server with Keycloak).
- `keycloak_kind.sh` + `keycloak-kind.yaml`: check 4, locally (below).

Option names are `src/tresor_secret.cpp`'s. Every value goes through a `tresor` secret's options; nothing is
written to disk but the test's own token file.

### The image (`ghcr.io/hugr-lab/tresor-live`)

`scripts/live/Dockerfile`, built by `.github/workflows/live-image.yml`: ubuntu 24.04 (`/bin/sh`, root, the
`ca-certificates` bundle), `/usr/local/bin/duckdb` (the CLI at the duckdb submodule's pin, bba7360),
`/opt/tresor/tresor.duckdb_extension` (tresor at the commit, unsigned: the CLI runs with `-unsigned`), and
`/live` (`check.sh`, `run.sh`, the SQL). The workflow builds like CI's Linux job (`GEN=ninja make`, CI's
ccache and vcpkg caches restore-only), checks that the image LOADs tresor and reaches an https host through
the image's CA bundle, and pushes with the workflow's own token, tagged with the short sha (and an optional
extra tag). tresor's OpenSSL is vcpkg's, whose compiled-in certificate directory is not Ubuntu's:
`SSL_CERT_FILE` / `SSL_CERT_DIR` point it at the bundle. linux/amd64 only.

A dispatch needs the workflow on the default branch: the PR's branch carried a temporary `push` trigger to
build the first images (`spec027-test`), removed before merge.

### Keycloak federated client authentication (verified in Keycloak's source and docs, 26.4-26.8)

- 26.4: `client-auth-federated` (preview): an identity provider (OIDC, SPIFFE) authenticates clients by
  assertions it issued. 26.5: the **Kubernetes** identity provider (`kubernetes-service-accounts`, preview).
  26.6: both `Type.DEFAULT` (`common/.../Profile.java`), on without a flag; SPIFFE stays preview.
- The client's authenticator is `federated-jwt` ("Signed JWT - Federated") with the client attributes
  `jwt.credential.issuer` (the identity provider's alias) and `jwt.credential.sub` (the token's `sub`,
  `system:serviceaccount:<namespace>:<name>`). The client is looked up by the assertion's issuer (the
  provider) and subject (`DefaultClientAssertionStrategy`); a `client_id` parameter, when sent, must name the
  same client (`AbstractJWTClientValidator`: "client_id parameter does not match authenticated client").
- The assertion's audience must be the realm's issuer URL, as Keycloak names itself from the request, and the
  only one (`FederatedJWTClientValidator`); a Kubernetes token may live at most 3600 s
  (`KubernetesIdentityProvider`) and may be reused.
- The provider loads the cluster's keys from `<issuer>/.well-known/openid-configuration`, with Keycloak's own
  service-account token when its `iss` is the provider's issuer, and trusts the cluster CA automatically
  (`--truststore-kubernetes-enabled`, default true). An in-cluster issuer
  (`https://kubernetes.default.svc.cluster.local`) therefore needs Keycloak inside that cluster; a public one
  (AKS's OIDC issuer) works anywhere.
- A realm created with the feature on has `federated-jwt` in its clients flow; an imported realm without flows
  gets it (checked: `realm-federated.json` names no flows).

tresor's `federated` flow is what Keycloak expects: a `client_credentials` grant with `client_id`,
`client_assertion_type` `urn:ietf:params:oauth:client-assertion-type:jwt-bearer` and `client_assertion` the
token as read from the file (`oidc_core.cpp`, `AddClientAuth`). No tresor change.

`server/testdata/keycloak/realm-federated.json`: the realm `federated`, the Kubernetes provider `kubernetes`
(issuer `https://kubernetes.default.svc.cluster.local`), the client `k8s-node` (`federated-jwt`, subject
`system:serviceaccount:tresor-logins:duckdb`, the audience mapper `duckdb-secrets`, the `client_id` note), its
service account with the realm role `nodes`. For AKS, the provider's issuer becomes the cluster's OIDC issuer
URL (`az aks show --query oidcIssuerProfile.issuerUrl`, trailing slash included).

### The ASSERTION_FILE mode

tresor checks the mode of a **key** file (`PRIVATE_KEY_FILE`: 600/400/640/440), not of a token file:
`ASSERTION_FILE` is read with no mode check (`ReadCredentialFile(…, false, …)`), as a projected token is
short-lived and audience-bound. A projected volume's default 0644 passes, and so does the stand's 0440 (read
by root, or by the pod's `fsGroup`). The stand runs the image as root.

## Enforcement & security

No token, identity header or secret is printed: the scripts mask anything shaped like a JWT, `run.sh` also the
platform's `IDENTITY_HEADER`; tresor's own errors never quote a credential. The image holds no credential; the
stand passes ids and URLs only. `TRESOR_KEYCHAIN=off` (`check.sh`, the image) / `memory` (`run.sh`): a
service's login never touches an OS credential store.

## Testing

- Locally, against the fake service (`test/fake/fake_service.py`, its `/msi/token` as `IDENTITY_ENDPOINT`):
  `run.sh managed_identity`, `mi_federated`, `k8s_entra`, `k8s_keycloak` pass; a wrong client fails.
- Locally, check 4 (`scripts/live/keycloak_kind.sh`, kind v0.30.0, Keycloak 26.8.1 in the cluster, ref-server on
  the host): the cluster mints a TokenRequest token for `tresor-logins/duckdb` with the realm as its audience
  (what a projected volume holds), written 0440; tresor logs in (`login=federated`, `role:nodes`,
  `client:k8s-node`); the token of `tresor-logins/default` is refused; the right token under another
  `CLIENT_ID` is refused. Not exercised locally: the kubelet's projected volume (mount, rotation) and the image
  (an arm64 host; the image is amd64) - the host's build ran the script.
- The workflow: the image LOADs tresor; discovery of github.com answers 404 over https (the CA bundle works).

## Results

| # | Check | Where | Result |
| --- | --- | --- | --- |
| 1 | `managed_identity` | Azure Container Apps job | pending |
| 2 | `federated` via the managed identity | Azure Container Apps job | pending |
| 3 | `federated`, projected token, Entra | AKS | pending |
| 4 | `federated`, Kubernetes token, Keycloak 26.8.1 | kind (local) | passed 2026-10-14 |
| 4b | the same, Keycloak in AKS with AKS's issuer | AKS | pending (optional) |

## Follow-ups

- The Azure results into the table and `website/docs/pipelines.md` ("checked live").
- Check 2's open point: tresor sends the managed identity's token only when its `aud` holds
  `api://AzureADTokenExchange` exactly; should Entra put the token-exchange app's GUID there, the check fails
  with "not meant for api://AzureADTokenExchange - not sent" and tresor would need to accept it.
