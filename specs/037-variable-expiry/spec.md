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
  3339; absent or `null`: no expiry). A service MUST mark such a value `sensitive`. A client caches it no longer
  than that (in practice until shortly before it) besides its other rules, not at all when it cannot read it; an
  expired value is served for that read and not kept. Optional both ways: a service that does not send it is
  complete, a client that does not know it ignores it.
- **Client**: a variable's value is cached until `ValidUntil` - its usual lifetime (30 s, or 5 minutes for a
  sensitive one), and with an `expires_at` until shortly before it (a margin of at most half its life, as a
  dynamic secret's material); an unreadable expiry, or an expired value, is served and not kept.
- **The generators are the service's** (tresor-server's `mint+…` once it supports variables, as for secrets' parameters - specs/029) and not
  part of the protocol. A separate `token()` function was considered and not taken: MotherDuck accepts no IdP
  token, so a token for it is the service's to mint anyway, and a variable carries it with nothing new in the
  client's surface.

## Design notes

- One rule for both fetches: `ValidUntil(root, now, lifetime, expiry_required)` serves a secret's material
  (required for a dynamic one, as before) and a variable's value. A static secret whose `expires_at` cannot be
  read is now not reused either (before: kept its 5 minutes) - a service's mistake is not trusted.
- A value not kept leaves no older one behind: the cache entry is removed.
- Once set, the token is MotherDuck's and DuckDB's: MotherDuck hides its setting (`current_setting` and
  `duckdb_settings()` answer `<redacted>`); in the connection string it is part of the ATTACH's path. The docs
  say both; tresor's protections end where the value leaves it.

## Testing

- `test/sql/attach/variable_expiry.test` (both clients), against the fake's generated variables (`mint+fake://`,
  a new value on each read): a long-lived value is generated once; one of six seconds is kept for three, then
  generated anew; an expired one and one with an unreadable expiry are generated on every read; the value goes
  into a DuckDB setting (`SET s3_region = corp.variable(...)`) as the recipe's `SET motherduck_token` would.
  The fake counts its generated values per process (a fresh fake per `test_attach.sh` run).
- `variables.test`'s listing includes the generated variables (sensitive).
- The recipe loads MotherDuck first: its setting exists only once the extension is loaded (`SET` does not
  autoload it; `md:` would, at the ATTACH that comes after).
- MotherDuck has no extension for DuckDB's 2.0 development line, so tresor and MotherDuck cannot meet in one
  DuckDB yet. The recipe's MotherDuck half was checked live on DuckDB 1.5.6 with a real token (2026-10-18): `SET
  motherduck_token = <an expression>` then `ATTACH 'md:'` connects, and the setting reads back `<redacted>`. (An
  expression as the ATTACH path is 2.0's: checked on our build, not with MotherDuck.) Again with tresor once
  MotherDuck ships for 2.0.

## Follow-ups

- tresor-server: generators in variables' values, and a MotherDuck rule (its session) - after this lands, as the
  protocol changes in tresor first.
