# Spec 016: what a service may refuse in a name, and an error that is not "try later"

- **Status**: implemented
- **Date**: 2026-10-01
- **Author**: hugr lab
- **Found by**: tresor-server (hugr-lab/tresor-server, phase 1)

## Summary

Two clarifications of `duckdb-secrets/1`. Neither changes a request or a response a client already
sends or reads.

1. **Names.** A service may refuse, with `422 invalid_secret`, a secret's name or a grant's id that:
   - is empty, or over 200 characters;
   - is not UTF-8;
   - begins or ends with whitespace;
   - holds a control character.

   tresor never sends one. A service whose store compares otherwise still compares exactly.
2. **`service_error` (500).** The service cannot serve the request, and retrying will not help until an
   operator acts: a value it holds no longer opens (its key changed), or its store is in a state it
   refuses. `503 service_unavailable` stays "try later".

## Problem

- **Names.** `protocol.md` said only "names are compared exactly".
  - SQL Server compares `'a'` and `'a '` as equal. A name with an edge space cannot be compared exactly
    there.
  - A control character in a name reaches logs and paths.
  - tresor-server refuses such names. The protocol gave it no word for that, and gave clients no rule
    to follow.
- **503 for a permanent failure.** tresor-server answered 503 to a value that does not decrypt
  (`ErrSealed`), because the protocol had no other type. 503 tells a client to try later, and nothing
  will change until an operator acts.

## Design

- **`protocol.md`, under General:**
  - the four refusable shapes;
  - "a client never sends one";
  - exact comparison whatever the store's collation.
- **`protocol.md`, Errors:**
  - `service_error | 500` is added;
  - `service_unavailable`'s meaning is sharpened;
  - a client that does not know a type acts on its status: a 4xx is a refusal of the request, a 5xx is
    the service's failure.
- **tresor:** `ProtocolName` (tresor_storage.cpp) refuses such a name at `CREATE PERSISTENT SECRET …
  IN corp`, before any request.
  - Characters are counted as code points.
  - Whitespace is Unicode's: space, NBSP, the U+2000 block and others.
  - Controls are C0, DEL and C1.
  - Grant ids are the client's own, derived from a role or a group, and never have such a shape.
- **The reference server:** `protocolName` refuses such a name on `PUT /v1/secrets/{name}`, and such an id
  on `PUT …/grants/{id}`, with 422. It never answers `service_error`: a store that does not decrypt
  stops it at start.
- **The audit:** a 500 is reason code `other`. TRSA's bounded list is unchanged.

## Enforcement & security

- A refused name is never sent, so it never reaches a service's logs or paths.
- `service_error` carries no value in its detail.

## Testing

- `test/sql/attach/writes.test`: an edge space and 201 characters are refused before any request.
- `server/internal/api`, `TestProtocolNames`:
  - refused: an edge space (leading, trailing, NBSP), a control, a tab, invalid UTF-8, 201 characters,
    and a grant id with an edge space;
  - accepted: 200 two-byte characters, and an inner space.

## Follow-ups

- An idea from the owner, not decided: `tresor_value('name')`, named values shared by users. It would
  be a protocol change here first.
