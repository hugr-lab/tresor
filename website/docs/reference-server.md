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
  - `iss` (verbatim: an issuer ending in `/`, like Auth0 or Entra v1, works), expiry, and the
    audience;
  - asymmetric algorithms only.

- Delegation: rules, grant exchange, the `Delegation` header, and actor policy. Only `shared` rules
  are supported.

Dynamic secrets and `user`-mode delegation are not implemented (`capabilities.dynamic` is false). Issuers must be https unless they are on loopback: their signing keys are
fetched from them.

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
    service: {claim: client_id}          # what marks a client-credentials token (see below)
policy:
  admins: [role:secrets_admin]
  create:
    - {principal: role:analysts, names: ["team_a_*"]}
    - {principal: client:etl, names: ["*"]}
  actors:                                # servers that may act for users, and with which verbs
    - {principal: client:acl-node, verbs: [use]}
```

## Who may do what

- **Principals.** Every caller is `subject:<issuer>|<sub>`, which is its identity. Its roles become
  `role:<name>` and its groups `group:<name>`.
- **Services.** A token is a service's only by its issuer's `service` rule: `claim` is present, and
  equals `equals` when that is set. The service then also gets `client:<name>`, taken from
  `client_claim` (default `azp`). No claim marks a service by convention. RFC 9068 puts `client_id`
  into every access token, a person's included. Without a rule, every caller is a person.
  - Keycloak: `{claim: client_id}`. The `service_account` scope sets it on client-credentials
    tokens only.
  - Entra: `{claim: idtyp, equals: app}`.
- **Verbs on a secret.** An admin holds every verb on every secret. The owner holds every verb on
  its own secret; the owner is the `subject:` that created it, a service's included. Everyone else
  holds the verbs of the grants made to their principals, and can grant on only the verbs they hold.
- **`client:` names are shared.** They carry no issuer, so with several issuers a `client:etl` in a
  policy or grant matches the `etl` of each. Name services by `subject:` where that matters.
- **Creating** is allowed to admins and to the `policy.create` rules, by name pattern.
- **Invisible secrets.** A secret you hold no verb on answers 404, exactly like one that does not
  exist.

## Delegation

- **Rules.** A secret's rules (`delegate` verb) name servers (`client:` principals) and users; only
  `shared` mode is supported.
- **Actors.** A server listed in `policy.actors` exchanges a user's token for a grant. The grant
  lives in memory only (8 h at most), is bound to that server, and is never logged.
- **Under a grant:**
  - every check uses the user's principals;
  - the actor's `verbs` only take away (management verbs are denied unless listed);
  - material needs a rule.

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
to include the person flow. To include the secrets case, seed a secret the conformance client may
use and name it: `TRESOR_CONFORMANCE_SECRET`, `_SECRET_TYPE`, `_SECRET_PATH` (covered by its scope),
`_SECRET_KEY` and `_SECRET_VALUE` (a VARCHAR parameter). `scripts/ci/test_keycloak.sh` runs the whole suite against the reference
server and Keycloak in docker.
