---
sidebar_position: 5
title: Reference server
---

# The reference server

`server/` in tresor's repository is a small implementation of the [`duckdb-secrets/1`](./protocol.md)
protocol in Go. It exists for two reasons: tresor's end-to-end tests run against it next to a real
Keycloak, and a company writing its own service can read it to see the protocol working end to end.
It is **not meant for production**: one process, one encrypted file, no high availability.

## What it implements

- Discovery and `whoami`.
- Secrets: list, read, create/replace with preconditions (`If-None-Match: *`, `If-Match`), delete,
  annotate.
- Grants.
- Token verification against any number of OIDC issuers:
  - the signature against the issuer's JWKS;
  - `iss`, expiry, and the audience;
  - asymmetric algorithms only.

Delegation and dynamic secrets are not implemented yet (`capabilities` says so).

## Run it

```bash
cd server
go build -o tresor-server ./cmd/tresor-server
TRESOR_SERVER_KEY=$(openssl rand -base64 32) ./tresor-server -config server.yaml
```

```yaml
listen: 127.0.0.1:8443
public_url: http://127.0.0.1:8443        # what discovery calls `api`
# tls: {cert: server.crt, key: server.key}   # required unless listening on loopback
store:
  path: data/secrets.enc                 # AES-256-GCM; omit for memory only
  key_env: TRESOR_SERVER_KEY             # 32 bytes, base64
issuers:
  - issuer: https://login.corp.example/realms/main
    audience: duckdb-secrets             # the token's `aud` must contain it
    client_id: duckdb                    # the public client people log in with
    scopes: [openid]
    human_flows: [authorization_code, device_code]
    service_flows: [client_credentials]
    roles_claim: realm_access.roles      # Keycloak; Entra/Okta: roles
    groups_claim: groups
policy:
  admins: [role:secrets_admin]
  create:
    - {principal: role:analysts, names: ["team_a_*"]}
    - {principal: client:etl, names: ["*"]}
```

## Who may do what

- **Principals.** Every caller is `subject:<issuer>|<sub>`. Its roles become `role:<name>` and its
  groups `group:<name>`. A client-credentials token also carries `client:<client_id>`: on Keycloak
  it has a `client_id` claim, and on Entra `idtyp` is `app`.
- **Verbs on a secret.** An admin holds every verb on every secret. The owner holds every verb on
  its own secret; the owner is whoever created it (a service owns what it creates). Everyone else
  holds the verbs of the grants made to their principals.
- **Creating** is allowed to admins and to the `policy.create` rules, by name pattern.
- **Invisible secrets.** A secret you hold no verb on answers 404, exactly like one that does not
  exist.

## Identity provider setup (Keycloak)

`server/testdata/keycloak/realm-tresor.json` is the realm the tests import. What matters for a real
deployment:

- A **public client for people** with the standard flow, PKCE `S256` and the redirect URI
  `http://127.0.0.1/*`. Keycloak accepts any port on a loopback redirect, as RFC 8252 requires.
  Enable the device grant if people log in over SSH.
- An **audience mapper** that puts the service's `audience` into access tokens, on the people's
  client and on every service client.
- **Service clients** with service accounts. A client created in the admin console gets the
  `service_account` scope, which adds the `client_id` claim. The imported test realm adds the same
  mapper by hand.

## Conformance

tresor's repository carries the conformance suite: sqllogictests in `test/sql/conformance/`, driven
against a service URL by environment variables. Build tresor, then:

```bash
TRESOR_CONFORMANCE_HOST=secrets.corp.example \
TRESOR_CONFORMANCE_INSECURE=false \
TRESOR_CONFORMANCE_ISSUER=https://login.corp.example/realms/main \
TRESOR_CONFORMANCE_CLIENT_ID=conformance TRESOR_CONFORMANCE_CLIENT_SECRET=… \
build/release/test/unittest --skip-error-messages '' 'test/sql/conformance/*'
```

Set `TRESOR_CONFORMANCE_PERSON=1` and a `BROWSER` that can complete your identity provider's login
to include the person flow. `scripts/ci/test_keycloak.sh` runs the whole suite against the reference
server and Keycloak in docker.
