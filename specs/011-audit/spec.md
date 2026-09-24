# Spec 011: audit and traces — what tresor did, for DuckDB's log and for OpenTelemetry

- **Status**: implemented
- **Date**: 2026-09-24
- **Author**: VGSML (with Claude)

## Summary

tresor records what it did as events:
- logins and logouts;
- secret lookups and refreshes, writes and drops;
- annotations, grants and revocations;
- on a duckdb-acl node, each session's delegation grant.

The events go to two places, each off unless someone asks:
- **DuckDB's own log**, through the setting `tresor_audit_level` (off by default);
- **the `tresor_audit` contract** (duckdb-ext-common spec 008, `TRSA` 1), where an exporter
  (acl-otel on a node) turns them into OpenTelemetry.

Under an acl session an event carries the statement's trace context. tresor also sends the
`traceparent` to the service, so tresor's work and the service's appear in the trace of the statement
that caused them.

## Problem

- **Nothing shows what tresor did.** On a person's laptop, an error message is all there is. On a
  node, acl-otel exports acl's audit, and tresor's part — which secret a session's statement used,
  whether its grant arrived, what the service refused — is missing.
- **Where the audit goes depends on where tresor runs.**
  - Installed locally, the audit has nowhere to go but DuckDB's log, and only when the person asks.
  - On a node, it belongs in the node's OpenTelemetry pipeline, in the statement's trace.
  - The service's own work is the service's to trace, continuing the same trace.

## Design

### The decisions (the owner's, 2026-09-24)

- **No per-session trace.** Events join the trace of their statement. A session-wide trace can come
  later if it is ever needed.
- **Locally, DuckDB's log**, behind a tresor setting that is off by default.
- **acl-otel only if it is there.** As with duckdb-acl's audit: nobody listening, nothing composed.
- **acl-otel's side** (consuming `TRSA`) is specced and built in duckdb-acl's repository, which edits
  acl-otel too.

### The producer (`src/tresor_events.{hpp,cpp}`)

- **`TresorAudit`**, one per instance in the ObjectCache:
  - it reaches the contract's registry at LOAD, so a consumer loaded later finds the same one;
  - it registers the `tresor` log type and the setting;
  - it starts the `Delivery` thread only at the first event a sink listens for, so a laptop without
    acl-otel runs no thread;
  - others hold it weakly (the secret storage outlives the ObjectCache); it goes before DuckDB's
    logger does.
- **`Audited`**, one operation:
  - built with its kind, filled with the caller, the secret and the target, finished with an outcome;
  - inert (nothing copied) when nobody listens;
  - one that ends without an outcome (an exception) is an error;
  - the time is measured only when a service call was made.
- **Emit.** The event is stamped and counted (`tresor.events` {kind, outcome, cached}). It is
  numbered under the lock around the push, so the sinks see the numbers in order. It is logged, and
  queued for the sinks. It never throws.
- **Cache hits** (a lookup served from memory) are counted, not emitted: a scan asks once per file.
  They are counted only while a sink listens, outside the storage's lock.

### What is emitted

| kind | where | outcome |
| --- | --- | --- |
| login | ATTACH: discovery, login, whoami, the first list | ok / error (`transport`, `invalid`, …) |
| logout | the catalog's end (DETACH, or the instance going) | ok |
| lookup | a service call for material (`LookupSecret`, `GetSecretByName`) | ok; denied (404/403 since the list, `mint_refused`); error; denied `no_grant`, once per acl session, for a session this node cannot act for |
| refresh | `RefreshMaterial` (httpfs's REFRESH auto) | as lookup |
| write / drop | `CREATE [OR REPLACE] PERSISTENT SECRET … IN corp`, `DROP` | the service's answer; `none` for an IF [NOT] EXISTS that changed nothing |
| annotate / grant / revoke | the management functions (`grants()` reads, not audited) | the service's answer; `target` = the role:/group: |
| session_grant | the actor | `detail`: obtained / failed / revoked / rejected / expired |

- **Who.**
  - `principal` is the login's subject from the ATTACH's whoami, as the protocol spells a principal:
    `subject:<issuer>|<sub>`.
  - `user` is the acl session's user (`subject:<issuer>|<sub>`).
  - `acl_session`, `correlation_id` and `traceparent` come from acl's `AclSessionView`. Only a
    well-formed `traceparent` (version 00, lower-case hex, non-zero ids) is carried or sent.
- **Reasons are tresor's own words.** Examples: "the service answered HTTP 403", a fixed text per
  exception class, or the part of tresor's message before the first `": "`, after which tresor
  quotes an IdP or a service. Nothing foreign reaches an event: it could quote a value, a URL or a
  token.
- **Reason codes** are the protocol's problem types (`no_verb`, `not_found`, `actor_not_allowed`,
  `mint_refused`), or else a status class (`unauthenticated`, `service_unavailable`, `invalid`,
  `other`), plus `transport` and `no_grant`.

### DuckDB's log

- **`tresor_audit_level`** (GLOBAL): `off` (default), `denied` (denied and error), or `all`.
  - Any other value is refused, and so is `SET SESSION`: the level is the instance's.
  - A value given before LOAD, as a config option, is applied at LOAD.
- **Where rows go.**
  - A row is written on the statement's own logger when there is a connection, so `duckdb_logs`
    names the connection and the query. It is written on the instance's logger for the actor's
    threads.
  - Rows are at `INFO`, or `WARNING` for refusals.
  - DuckDB keeps a row only while its own logging is on for the `tresor` type
    (`CALL enable_logging('tresor')`); DuckDB decides where logs are stored.
- **The `tresor` log type is structured** (a STRUCT of the event's fields and `seq`), so
  `duckdb_logs_parsed('tresor')` has a column each.

### Tracing to the service (protocol, normative)

- **Sending.** `Caller::Call` adds `traceparent` when the statement has a well-formed one. That
  happens only under an acl session, the only place a trace context comes from today.
- **`protocol.md` gains Tracing.**
  - A client may send `traceparent`.
  - A service SHOULD continue the trace with its own spans and OpenTelemetry.
  - It MUST NOT trust the header for anything but correlation.
  - It ignores a malformed one.
- **The reference server** logs `trace_id` and `parent_span_id` from a well-formed header with the
  request line. It exports no spans; "our future service" would.

## Enforcement & security

- **No credential in an event:**
  - no material, token, session handle, grant id or statement text;
  - no foreign text in `reason`;
  - the revocation's error names the HTTP status only (a service's problem could quote the path, and
    the grant id is in it).
- **Metric attributes are bounded:** only `kind`, `outcome` and `cached`. Names and subjects never
  label a metric.
- **The audit never fails what it describes:** `Emit` catches everything, and delivery drops (and
  counts) rather than blocks.
- **A registry of another `TRSA` version, or another hooks base, is refused by `Reach`:** tresor then
  logs only, and acl-otel reports the mismatch.

## Testing

`test/sql/attach/audit.test`, against the fake service:
- **The setting:** its default, and a bad value refused.
- **Level `off`:** no rows.
- **Level `all`:**
  - a login and a lookup, typed, with `principal` and timing;
  - a cache hit not logged.
- **Level `denied`:**
  - a `mint_refused` refusal at `WARNING`, with tresor's own reason;
  - an ok lookup not logged.
- **A recording sink** (`acl_stub_audit_listen`/`_last`, the test stand-in for acl-otel):
  - the session's grant obtained and revoked;
  - a lookup under the session carries the session, the user, the correlation id and the
    traceparent;
  - a malformed traceparent is neither carried nor sent;
  - the logout.
- **The service saw the header:** the fake's `traced` secret echoes the `traceparent` it received.
- **Nothing tresor logged** contains the client secret, the session token or a grant id.

Go: `TestTraceIDs` checks the reference server's parsing: a valid header, and malformed or forged
ones refused.

## The review's findings (applied)

- **HIGH: a lookup refused with 404/403 put the service's problem text in `reason`.** It is now
  "the service answered HTTP <status>", and a test pins it (a listed secret whose material is gone,
  with a detail quoting it).
- **The cache-hit path paid for a counter under the storage's lock, with nobody listening.** It now
  counts only while a sink listens, outside the lock.
- **`SET SESSION` changed every connection, and a value set before LOAD was shown but not applied.**
  `SET SESSION` is refused, and a value set before LOAD is applied at LOAD.
- **A `no_grant` refusal was emitted for every file a session read.** It is emitted once per session.
- **IF [NOT] EXISTS no-ops were errors.** They are `none` now, the outcome the contract defined and
  nothing emitted.
- **Smaller fixes:**
  - only traceparent version `00` is sent, as the reference server reads it;
  - write and drop are timed when their call throws;
  - an obtained grant is timed;
  - a revocation skipped at DETACH is told;
  - the pointer to the operation in the management call's data is cleared;
  - `principal` is bounded;
  - the contract says a sink must not reach the ObjectCache;
  - the test recorder is kept per instance.
- **New tests:**
  - write/none, grant, revoke, drop/none;
  - `SET SESSION` refused;
  - a non-00 traceparent;
  - the 404 reason.
- **Not taken:**
  - login failures are still classified by exception class: a refused list at ATTACH reads
    `transport`, now worded "failed, or could not be reached";
  - the logout at DETACH is on the instance's logger;
  - the ext-common pin moves to `v0.7.0` before merge (and CLAUDE.md's pin table with it).

## Checked live (2026-09-24)

`scripts/dev/otel_live.sh` (a bench, not CI) runs tresor, duckdb-acl (72734f6) and acl-otel (main, its
spec 011) in one DuckDB against Keycloak, the reference server and acl-otel's local stack. alice's
statement, under her acl session with `SET acl_traceparent`, reads the echo API with a token minted for
her. What arrived:

- **Tempo:** in the caller's trace, `acl SELECT` (acl-otel) and `tresor.lookup` (scope `tresor`), both
  children of the caller's span.
- **Loki:** the records login, session_grant (obtained), lookup, session_grant (revoked), logout.
- **The reference server's log:** both service calls of the statement (the list, the material), each
  with the same `trace_id` and the caller's span as `parent_span_id`.
- **The echo API:** `aud=echo-api user=alice`.

Found and fixed here: `principal` was whoami's bare `sub`. It is now `subject:<issuer>|<sub>`, as
the protocol spells a principal and as `user` already was.

Seen, for acl and acl-otel:
- `tresor.lookup` is a sibling of `acl SELECT`, not its child, because acl publishes the caller's
  `traceparent`, not its own statement span;
- acl-otel's `acl_otel_status().tresor` counted 5 events but `records.sent` and `spans.sent` 0,
  while Loki and Tempo had them.

## Follow-ups

- acl-otel consumes `TRSA` 1 (task handed to duckdb-acl): OTLP logs, spans parented by the event's
  `traceparent`, and the `tresor.*` metrics.
- A session-wide trace, if the owner wants one.
- Gauges (live grants, cached materials) when a consumer asks for them.
