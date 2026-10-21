# Spec 017: the first release - what is ready, what waits for DuckDB 2.0

- **Status**: accepted (the checklist brought up to date by [035](../035-release-readiness/spec.md); run by
  [038](../038-repin-v2.0.0/spec.md) - the pins - and [039](../039-release-0.1.0/spec.md) - the release)
- **Date**: 2026-10-01 (checklist updated 2026-10-17)
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
  - wasm excluded (no loopback listener or device polling in a browser). Since specs/020 the page logs in
    and wasm compiles; it stays excluded until duckdb-wasm is on DuckDB 2.0 (the owner's decision, specs/035);
  - `version` and `repo.ref` at `0.1.0` / `v0.1.0`, set at the release;
  - the hello world.
- **The README** also gains the build's missing step (`make vcpkg-setup`) and a link to tresor-server.
- **Stale follow-ups.** A spec's *Follow-ups* list keeps its items; those done since are marked with
  the spec that did them.

## The release checklist (when DuckDB 2.0 is tagged)

Updated by specs/035 (2026-10-17) for specs 018-034.

1. **Pins, together** with duckdb-acl and acl-otel (one duckdb commit for the three), as the re-pins did
   (specs/014 ... 034):
   - the duckdb submodule moves to the `v2.0.0` tag;
   - `distribution.yml`: `duckdb_version: v2.0.0`;
   - the test-only extensions at the tag's own pins (`duckdb/.github/config/extensions/<name>.cmake`):
     httpfs, postgres_scanner, iceberg and avro in `extension_config.cmake`;
     `scripts/ci/check_extension_pins.sh` (CI's lint) checks every `GIT_TAG` against duckdb's;
   - extension-ci-tools at the release's branch (it cuts one per release, `v2.0.0`): the submodule,
     and in `distribution.yml` both `uses: …@v2.0.0` and `ci_tools_version: v2.0.0`;
   - `ACL_COMMIT` moves to duckdb-acl's release commit (a merged one, on its main);
   - duckdb-ext-common: v0.13.0 today, the same tag as duckdb-acl; the three repositories' tags carry the
     same contract stamps - ACLC: `acl_checkout.sh` checks it; TRSA: acl-otel's TRSA test, and `contracts/`
     equal between the tags; acl-otel re-pinned to the same duckdb commit, its TRSA test green;
   - `CLAUDE.md`'s pin table and the CHANGELOG's "Built for DuckDB 2.0" line name the tag.
2. **The gate**:
   - CI green: lint (with the pin check), the reference server, the web helper; Linux with the unit and
     attach suites on both HTTP clients and `test_keycloak.sh` with the real duckdb-acl; the consumers job
     (httpfs, postgres_scanner, iceberg against a real Postgres, specs/033). macOS runs the unit and attach
     suites on the built-in client, on push only (not on PRs): check a main or tag run;
   - the distribution build on all six platforms;
   - `make wasm_eh` compiles, by hand with emsdk 3.1.71 (specs/020; wasm is not in CI, not distributed);
   - the embedder (`test/sql/embedded.test`, specs/024) green, and hugr-node building `hugr_node` with tresor's
     release commit;
   - before the tag, the live checks: Entra by hand (`scripts/dev/entra_live.sh`, specs/013) and the federated
     node (`.github/workflows/entra-live.yml`); the pipelines' logins (`scripts/live/`, the `tresor-live`
     image from `.github/workflows/live-image.yml`, specs/027) on Azure and on kind.
3. **The protocol becomes normative**: the *Draft* banner on `protocol.md` is replaced by "version 1";
   from then on a change is a new version.
4. **The version**: `CHANGELOG.md`'s *Unreleased* becomes `[0.1.0] - <date>`, and the tag is `v0.1.0`.
   DuckDB's build sets `EXT_VERSION_TRESOR` from `git describe --tags` when the tag is checked out (a
   checkout without it gives the commit). Check it on the tag's distribution artifact:
   `SELECT tresor_version()` returns `v0.1.0`.
5. **Publishing**: a PR to duckdb/community-extensions with
   `description.yml`, its `ref` being the tag; hugr lab's own repository too, once it exists (specs/035).
   - Their CI builds and runs the tests. Before the PR, check how their runner treats
     `require-env TRESOR_TEST_PORT` (the tests that need a service should skip), and tresor loaded by
     build path.
   - Fall back to `test_config` with a skip, as mssql-extension does.
   - Their build sets no `TRESOR_TEST_HTTPFS`: the tests that need httpfs, acl_stub, typed_secret_stub or the
     embedder (`require`, `require-env TRESOR_TEST_HTTPFS`) skip there, and so do the consumer tests
     (`test/sql/consumers/*`: `require iceberg`, `require-env TRESOR_TEST_CONSUMERS` / `TRESOR_TEST_PG_PORT`),
     which is right for them; CI's floors (`assert_ran.sh`) are ours.
6. **The docs**: the home page's and the README's status notes say "released", getting started installs
   from `community` and drops its "Before the first release" note. `web.md`'s "Not yet in a browser" stays
   until duckdb-wasm is on DuckDB 2.0.
7. **After the tag**: hugr-node re-pins tresor (and duckdb-acl) at the release commits (specs/024).

## Decided (2026-10-01)

- **The first version is `0.1.0`.** The tag is `v0.1.0`.
- **Published to both**, after DuckDB 2.0's release:
  - hugr lab's own extension repository (still to come; as soon as it exists - not a condition of the release,
    specs/035): an external repository of the kind DuckDB 2.0
    supports, which signs what it serves with its own key. Nodes trust that key and need no
    `allow_unsigned_extensions`.
  - duckdb/community-extensions, signed, through their review.

## Testing

Docs only, and new files: the docs build (`onBrokenLinks: throw`) and the link check.
