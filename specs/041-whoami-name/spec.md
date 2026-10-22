# Spec 041: whoami names the person - an optional `name`, for people to read

- **Status**: implemented
- **Date**: 2026-10-22
- **Author**: hugr lab
- **Asked by**: found by the owner's announcement run (2026-10-21): `whoami` showed a person as Keycloak's `sub`
  (a UUID) - Entra's is an object id - and nothing a person reads

## Summary

- **Protocol** (an addition version 1 allows: a field a client may ignore): `GET /v1/whoami` MAY carry
  `name`, who the subject is for people to read (tresor-server and the reference server: the token's
  `preferred_username`, else `name`, else `email`). It identifies nothing - grants and the audit go by
  `subject` - is absent when the token carries none, and under delegation is the user's.
- **Client**: `corp.whoami()` gains a `name` column after `subject` (VARCHAR, NULL when the service gives none).
- **Reference server**: `name` from the verified token's claims, in that order.
- **Docs**: `concepts.md` says what whoami shows, and how to keep an identity provider's extra roles (Keycloak's
  `default-roles-<realm>`, `offline_access`, `uma_authorization`) out of the list - a client role mapper, or
  the service's filter (tresor-server's to offer). `clients.md` suggests the device flow in DuckDB UI, where a
  short URL and a code read better than the browser flow's long link (now that the device flow works at
  Keycloak, specs/040).

The audit is unchanged (TRSA: its principal stays the subject; adding a name would be a layout change).

## Testing

- The fake service names alice (`alice@corp.example`) and bob, not the services: `person_login.test` reads the
  name, `service_login.test` reads NULL.
- Real Keycloak (`test_keycloak.sh`): `reference_server/keycloak.test` - alice is `alice`, the etl service account
  `service-account-etl`; `reference_server/actor.test` - under alice's delegation grant the node's whoami names
  alice.
- The reference server's Go test: `preferred_username` before `name` before `email`; absent without them.
