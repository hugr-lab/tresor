# server/ — the reference duckdb-secrets/1 server

A small implementation of the [`duckdb-secrets/1` protocol](../website/docs/protocol.md) in Go
(specs/003). It exists for tresor's end-to-end tests and conformance suite, and as an example for
anyone writing a service. It is not meant for production.

```bash
go build -o tresor-server ./cmd/tresor-server
./tresor-server -config server.yaml        # the config is described in website/docs/reference-server.md
go test ./...                              # token verification, every route, the encrypted store
docker compose -p tresor-kc up -d          # Keycloak with the test realm (testdata/keycloak), 127.0.0.1:18480
```

Layout:

- `cmd/tresor-server` — the binary.
- `internal/config` — YAML and its validation.
- `internal/auth` — verification and principals.
- `internal/store` — the encrypted store.
- `internal/api` — the routes and permissions.
- `internal/testidp` — an in-process issuer for the tests.

From the repository root, `scripts/ci/test_keycloak.sh` runs tresor's conformance suite against this
server and Keycloak.
