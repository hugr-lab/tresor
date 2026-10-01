# Spec 017: the first release - what is ready, what waits for DuckDB 2.0

- **Status**: accepted (the release itself waits for DuckDB 2.0; version and channels decided)
- **Date**: 2026-10-01
- **Author**: hugr lab

## Summary

tresor's first release ships with DuckDB 2.0: the owner's decision. Until then, everything that does
not depend on DuckDB's tag is done now, so that the release is mechanical:
- the texts that still said "being built";
- a CHANGELOG;
- the community-extensions descriptor;
- the checklist below.

## What is done here

- **The status texts.**
  - The site's home page, getting started and the README said only attaching and whoami worked.
    They now say what works, and that until the release tresor is built from source.
  - The protocol page keeps its *Draft* banner, because the protocol becomes normative with the
    release. Its conformance paragraph now lists what the suite checks.
- **`CHANGELOG.md`** (Keep a Changelog, SemVer): an *Unreleased* section, one line per feature with
  its spec.
- **`description.yml`**, the descriptor duckdb/community-extensions builds from:
  - name, description, `licence: MIT`, the maintainer;
  - wasm excluded (no loopback listener or device polling in a browser);
  - `version` and `repo.ref` at `0.1.0` / `v0.1.0`, set at the release;
  - the hello world.
- **The README** also gains the build's missing step (`make vcpkg-setup`) and a link to tresor-server.
- **Stale follow-ups.** A spec's *Follow-ups* list keeps its items; those done since are marked with
  the spec that did them.

## The release checklist (when DuckDB 2.0 is tagged)

1. **Pins, together** with duckdb-acl and acl-otel (one duckdb commit for the three):
   - the duckdb submodule moves to the `v2.0.0` tag;
   - `distribution.yml`: `duckdb_version: v2.0.0`;
   - httpfs at the tag's own pin (`duckdb/.github/config/extensions/httpfs.cmake`);
   - extension-ci-tools at the release's branch (it cuts one per release, `v2.0.0`): the submodule,
     and in `distribution.yml` both `uses: …@v2.0.0` and `ci_tools_version: v2.0.0`;
   - `ACL_COMMIT` moves to duckdb-acl's release commit;
   - duckdb-ext-common: the three repositories' tags carry the same contract stamps (ACLC, TRSA);
     acl-otel re-pinned to the same duckdb commit, its TRSA test green.
2. **The gate**: CI green, the distribution build on all six platforms, and `test_keycloak.sh` with
   the real duckdb-acl. Before the tag, one live Entra run (`scripts/dev/entra_live.sh`).
3. **The protocol becomes normative**: the *Draft* banner on `protocol.md` is replaced by "version 1";
   from then on a change is a new version.
4. **The version**: `CHANGELOG.md`'s *Unreleased* becomes `[0.1.0] - <date>`, and the tag is `v0.1.0`.
   DuckDB's build sets `EXT_VERSION_TRESOR` from `git describe --tags` when the tag is checked out (a
   checkout without it gives the commit). Check it on the tag's distribution artifact:
   `SELECT tresor_version()` returns `v0.1.0`.
5. **Publishing**: to hugr lab's repository, then a PR to duckdb/community-extensions with
   `description.yml`, its `ref` being the tag. Their CI builds and runs the tests. Check before the PR how their runner treats
   `require-env TRESOR_TEST_PORT` (the tests that need a service should skip), and tresor loaded by
   build path. Fall back to `test_config` with a skip, as mssql-extension does.
6. **The docs**: the home page's status note says "released", and getting started installs from
   `community`.

## Decided (2026-10-01)

- **The first version is `0.1.0`.** The tag is `v0.1.0`.
- **Published to both**, after DuckDB 2.0's release:
  - hugr lab's own extension repository (still to come). Its binaries are unsigned, so nodes run with
    `allow_unsigned_extensions` (`duckdb -unsigned`).
  - duckdb/community-extensions, signed, through their review.

## Testing

Docs only, and new files: the docs build (`onBrokenLinks: throw`) and the link check.
