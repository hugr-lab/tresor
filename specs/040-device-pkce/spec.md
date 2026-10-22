# Spec 040: a person's device login at a Keycloak that enforces PKCE

- **Status**: accepted (duckdb-ext-common spec 017 merged and tagged: then the pin)
- **Date**: 2026-10-22
- **Author**: hugr lab
- **Asked by**: found by the owner's announcement run (2026-10-21): `tresor_login(…, login := 'device')` against
  tresor's own Keycloak test realm failed - `invalid_request: Missing parameter: code_challenge_method`

## Summary

A Keycloak public client with PKCE enforced (the test realm's `duckdb`, and a common setting) requires PKCE on the
device authorization request too. The OIDC core sent none, so every device login there failed: `ATTACH … (LOGIN
'device')`, `tresor_login(…, login := 'device')`, and `LOGIN 'auto'` on a machine without a browser. The device
flow had been tested against the fake IdP only.

- **The core** (duckdb-ext-common spec 017): discovery reads `code_challenge_methods_supported`; the device
  request carries an S256 challenge when the issuer lists S256, and the poll the verifier. An issuer that lists
  none (Entra) is sent none - unchanged.
- **tresor** passes the verifier from `DeviceBegin` to `DevicePoll` in both device paths (the ATTACH's and
  `tresor_login`'s background thread).

## Testing

- duckdb-ext-common's own test (a fake IdP enforcing PKCE as Keycloak does).
- `scripts/ci/test_keycloak.sh` now logs a person in by the device flow at the real Keycloak (its `duckdb` client
  enforces PKCE): `ATTACH … (LOGIN 'device')`, the code approved by `test/keycloak/device.py` through the link
  with the code (Keycloak's form takes no typed code outside a browser session), then `whoami` says `device`.
- The fake service's device tests (no PKCE advertised) are unchanged.

## Follow-ups

- duckdb-acl's device flow (its OIDC secret) passes the verifier when it moves to the same ext-common tag (the
  family moves together: hugr-node checks the copies match).
