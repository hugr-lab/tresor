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
4. **The gate** (017 item 2), at 036180c: CI green on Linux and macOS (main's push run - macOS runs on push
   only), the consumers job, the Distribution build on every platform, `test_keycloak.sh` with real duckdb-acl
   (specs/038). The live Entra run (`scripts/dev/entra_live.sh`) before the tag.
5. **The tag `v0.1.0`** on the merged commit, then the Distribution build of the tag: `SELECT tresor_version()`
   on its artifact answers `v0.1.0`. The docs site then serves 0.1.0 at its root (pages.yml snapshots the tag).
6. **Publishing**: a PR to duckdb/community-extensions with `description.yml` (`repo.ref` the tag's commit, as
   their descriptors take it); hugr lab's own repository once it exists (specs/035).

Steps 5 and 6 are outward and not undone: each waits for the owner's word, as this PR does.

## Testing

Docs only here: the docs build (`onBrokenLinks: throw`) and `check_docs_links.py`.
