# Spec 026: pipelines - a service identity, never a person's login

- **Status**: implemented
- **Date**: 2026-10-14
- **Author**: hugr lab
- **Asked by**: the owner: how an ETL job on a remote executor connects

## Summary

A pipeline is not a person: it logs in as a **service** with a `tresor` secret, and an administrator grants its
role `use` on what it reads (specs/009). Every flow it needs exists (specs/002, 013, 015); what is missing is the
guidance. This spec is documentation, plus one decision.

## Design

A docs page, "Pipelines", with a recipe per executor, best first:

| Where it runs | Flow | Secret on the machine |
| --- | --- | --- |
| Kubernetes (AKS, EKS, GKE, any) | `federated`, the projected service-account token (`ASSERTION_FILE`) | none |
| GitHub Actions | `federated`, `ASSERTION_SOURCE 'github_actions'` (checked live, specs/013) | none |
| Azure (VM, App Service, Functions, Container Apps; on AKS, workload identity: the Kubernetes row) | `managed_identity`, or `federated` through it | none |
| A VM or a worker with no platform identity | `client_credentials` with a private key (`private_key_jwt`) | a key file (0600) |
| Last resort | `client_credentials` with a client secret | a shared secret |
| A token already held | `FLOW 'token'` | a token, which expires |

- The setup in SQL (`CREATE SECRET (TYPE tresor, SCOPE 'tresor:host', FLOW ...)`, then `ATTACH`), and in
  dbt-duckdb's profile (its `secrets` and `attach`).
- Renewal: client credentials are minted again, a federated token file read again at each mint - a long job does
  not fall off.
- Many workers (Spark, Ray, parallel tasks): each process logs in by itself; the IdP sees one login per process.
- The identity provider's side: the service's client and its role on the API (Keycloak, Entra), and the service's
  discovery listing the flow (`service_flows`).

**Decision: no person's login on a schedule.** A job that runs "as the analyst" would need the person's refresh
token on a server. It is not supported: a scheduled job gets a service identity with a role. Said in the docs.

**Not now**, recorded as candidates: a `tresor` secret from environment variables (ATTACH with no SQL about the
login), and `ASSERTION_SOURCE 'gcp_metadata'` (GCE's identity token) - each its own spec when asked for.

## Testing

`npx docusaurus build` (links, anchors); the recipes' SQL is what the existing tests run
(`service_identities.test`, `service_login.test`, the Entra live run).

## Checked

- The page: `website/docs/pipelines.md`. Its SQL is the tests' (option names from `src/tresor_secret.cpp`).
- dbt-duckdb (main at ef78e1f, 2026-10-05), read in its source: `extensions` (a `name`/`repo` entry runs
  `install <name> from <repo>` with the repo pasted unquoted), then `secrets` (`CREATE OR REPLACE SECRET <name>
  (type tresor, <key> '<value>', …, scope '…')`, temporary), then `attach` (`ATTACH IF NOT EXISTS '<path>' AS
  <alias> (SECRET <name>, …)`, a `true` option as a bare keyword). That SQL, as dbt-duckdb renders it, logged in
  against the fake service (`client:etl`, `client_credentials`): the profile's shape; the page's
  profile shows `federated`, whose options are the tested ones.
