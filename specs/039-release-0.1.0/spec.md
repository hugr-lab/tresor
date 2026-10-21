# Spec 039: the first release - tresor 0.1.0 for DuckDB 2.0.0, the protocol's version 1

- **Status**: accepted (the release PR; the tag and the publishing follow, each on the owner's word)
- **Date**: 2026-10-21
- **Author**: hugr lab
- **Asked by**: the owner (2026-10-21), once DuckDB v2.0.0 was out and the family re-pinned (specs/038)

## Summary

specs/017's checklist, run. Its first item (the pins) was specs/038; this spec does the rest:

1. **The protocol becomes normative**: `protocol.md`'s *Draft* banner is now "version 1". An addition a client or
   a service may ignore (an optional field, an optional resource advertised in discovery - as specs/018's
   variables and specs/037's `expires_at` were) keeps the version; any other change is a new version.
2. **The version**: `CHANGELOG.md`'s *Unreleased* becomes `[0.1.0] - 2026-10-21`, with the compare links.
3. **The docs say released**: the home page's status, getting started's install (`INSTALL tresor FROM
   community;` - the "before the first release" note goes), the README.
4. **The gate** (017 item 2):
   - CI at 036180c, green on Linux and macOS (main's push run - macOS runs on push only), the consumers job,
     the embedder (`tresor_embedder`, as hugr-node builds tresor in) included;
   - `test_keycloak.sh` with real duckdb-acl, `make wasm_eh` by hand - both at d54cbbe (specs/038);
   - the Distribution build on every platform: green on the branch before specs/038 merged; main's run of
     036180c is re-checked before the tag;
   - live with Entra (`scripts/dev/entra_live.sh`, 2026-10-21): a node with its certificate and with its client
     secret logged in and listed; the person's browser step and the secret it creates were checked live at
     specs/013 and are not repeated unless the owner asks. Not re-run: the federated node (`entra-live.yml`)
     and the pipelines' live checks (specs/027, Azure and kind - the stand is gone): no login code changed
     since (specs/036 adds a check in front of the transport, covered on both clients by the suites).
   - hugr-node building `hugr_node` with tresor and acl at these pins: its own session, after the tag.
5. **The tag `v0.1.0`** on the merged commit, then the Distribution build of the tag: `SELECT tresor_version()`
   on its artifact answers `v0.1.0`. The docs site then serves 0.1.0 at its root (pages.yml snapshots the tag).
   If the tag is later than 2026-10-21, that date moves in CHANGELOG, the protocol's banner and here together.
6. **Publishing**: a PR to duckdb/community-extensions with `description.yml`, `repo.ref` the tagged commit's
   full SHA (a tag can move; their descriptors take the commit; their build passes the ref to checkout, so a tag
   would work too). Their CI builds DuckDB v2.0.0 (d54cbbe, our pin) with extension-ci-tools' `v2.0-cyanoptera`
   (it now carries #432/#434) and runs the tests: those needing a service skip on `require-env` (no
   `TRESOR_TEST_PORT` there), and none needs tresor linked (they load it by build path - our Distribution build,
   the same workflow, runs them so).
   No `ref_next` (only for a DuckDB other than the latest stable). Then hugr lab's own repository once it exists
   (specs/035), and hugr-node re-pins to the tag's commit (017 item 7).

Steps 5 and 6 are outward and not undone: each waits for the owner's word, as this PR does.

## Testing

Docs only here: the docs build (`onBrokenLinks: throw`) and `check_docs_links.py`.
