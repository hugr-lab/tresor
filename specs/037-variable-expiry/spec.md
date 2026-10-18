# Spec 037: a variable's value with an expiry - a generated token into a DuckDB setting (MotherDuck)

- **Status**: implemented
- **Date**: 2026-10-18
- **Author**: hugr lab
- **Asked by**: the owner: MotherDuck's token through a tresor variable - `SET motherduck_token =
  corp.variable(...)` - with a value the service may generate per caller

## Summary

MotherDuck reads no DuckDB secret: its token is the `motherduck_token` setting (or the connection string).
DuckDB 2.0 takes an expression in both - `SET motherduck_token = corp.variable('md_token')`, and an ATTACH path
built from one (checked) - so a tresor variable already carries a stored token, or a reference the service
resolves (specs/018). What was missing is a value the service **generates on each read**, such as a MotherDuck
token tresor-server mints for the caller: its life may be shorter than the client's cache of a sensitive value
(a secret's material, 5 minutes), so it must say when it expires.

- **Protocol** (`website/docs/protocol.md`, Variables): `GET /v1/variables/{name}` MAY carry `expires_at` (RFC
  3339). A value with one is also `sensitive`. A client caches it no longer than that (in practice until shortly
  before it), and not at all when it cannot read it. Optional both ways: a service that does not send it is
  complete, a client that does not know it ignores it.
- **Client**: a variable's value is cached until `ValidUntil` - its usual lifetime (30 s, or 5 minutes for a
  sensitive one), and with an `expires_at` until shortly before it (a margin of at most half its life, as a
  dynamic secret's material); an unreadable expiry, or an expired value, is served and not kept.
- **The generators are the service's** (tresor-server: `mint+…`, as for secrets' parameters, specs/029) and not
  part of the protocol. A separate `token()` function was considered and not taken: MotherDuck accepts no IdP
  token, so a token for it is the service's to mint anyway, and a variable carries it with nothing new in the
  client's surface.

## Design notes

- One rule for both fetches: `ValidUntil(root, now, lifetime, expiry_required)` serves a secret's material
  (required for a dynamic one, as before) and a variable's value. A static secret whose `expires_at` cannot be
  read is now not reused either (before: kept its 5 minutes) - a service's mistake is not trusted.
- A value not kept leaves no older one behind: the cache entry is removed.
- Once set, the token is DuckDB's: `current_setting` shows it unless MotherDuck hides its setting; in the
  connection string it becomes the database's path. The docs say both; tresor's protections end where the value
  leaves it.

## Testing

- `test/sql/attach/variable_expiry.test` (both clients), against the fake's generated variables (`mint+fake://`,
  a new value on each read): a long-lived value is generated once; one of six seconds is kept for three, then
  generated anew; an expired one and one with an unreadable expiry are generated on every read; the value goes
  into DuckDB (`SET VARIABLE`) as a setting would take it.
- `variables.test`'s listing includes the generated variables (sensitive).
- MotherDuck itself is not built here (no `motherduck` extension in the test build): the recipe is the
  documented `SET`.

## Follow-ups

- tresor-server: generators in variables' values, and a MotherDuck rule (its session) - after this lands, as the
  protocol changes in tresor first.
