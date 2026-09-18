# server/ — the reference duckdb-secrets/1 server

A minimal implementation of the [`duckdb-secrets/1` protocol](../website/docs/protocol.md), kept
here for two reasons:

1. **Tests.** tresor's integration and conformance tests need a service to talk to; CI runs this
   server next to an identity provider in a container (Keycloak).
2. **An example.** A company writing its own service — in front of Vault/OpenBao, a cloud key
   vault, or a table of its own — reads this one to see the protocol end to end.

It is deliberately small: token verification against the configured issuers (JWKS, `iss`, `aud`,
expiry), claims → principals, an encrypted local store, grants, and optional delegation. It is not
meant for production.

**Not implemented yet** — language (Go is the working choice, next to hugr) and scope are decided in
its own spec.
