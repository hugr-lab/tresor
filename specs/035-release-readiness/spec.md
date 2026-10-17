# Spec 035: release readiness - specs 018-034 checked against the first release

- **Status**: implemented
- **Date**: 2026-10-17
- **Author**: hugr lab

## Summary

The first release (0.1.0) ships with DuckDB 2.0, which is not tagged yet. Spec 017 (2026-10-01) prepared
everything that does not wait for the tag. Specs 018-034 landed since. This pass brings the release's texts
and checklist up to date with them, so that the release stays mechanical. Docs and metadata only: no code
changes.

## What was checked, and changed

- **`CHANGELOG.md`** (*Unreleased*): new lines for typed secrets (032), the consumer tests (033), embedding
  (024), the platforms (Windows with clang-cl, 022; wasm compiles, not distributed, 020) and one line for the
  re-pins (014, 019, 021, 023, 028, 031, 034: DuckDB `v2.0-cyanoptera` at f8f3f4d, duckdb-ext-common v0.13.0).
  Already covered: 007 and 009 (the writes and grants line), 010 (dynamic secrets), 013 and 015 (the service
  logins), 016 (the protocol line). Nothing internal is listed.
- **specs/017's checklist**, edited in place (it is kept current, no decision reversed; noted at its top):
  - the test-only extensions that move with the duckdb pin (httpfs, postgres_scanner, iceberg, avro), checked
    by `scripts/ci/check_extension_pins.sh`;
  - duckdb-ext-common at v0.13.0, the same tag as duckdb-acl, its stamps checked by `acl_checkout.sh`;
  - the gate: the consumers CI job, `make wasm_eh`, the embedder and hugr-node's build (024), the live checks.
    `scripts/dev/entra_live.sh` exists and is the right reference (spec 027 added `scripts/live/` and the
    `tresor-live` image beside it, it replaced nothing), plus `.github/workflows/entra-live.yml`;
  - what community-extensions' runner skips (no `TRESOR_TEST_HTTPFS` there);
  - the docs to change at the release (README, home page, getting started; `web.md`'s caution stays);
  - hugr-node re-pinning tresor after the tag.
- **`description.yml`**: the extended description now names `tresor_login` (DuckDB UI, notebooks, IDEs),
  `tresor_logoff`, the service logins as they are (a key, a federated token from Kubernetes or GitHub Actions,
  a managed identity, a client secret, a token), any parameter generated per caller, and variables. Its
  comment records why wasm is excluded. The maintainer `VGSML` is the owner's GitHub account (the author of
  the merged PRs).
- **`distribution.yml`**: the comment on `exclude_archs` gave spec 017's reason (no loopback listener in a
  browser), which specs/020 removed; it now gives the current one. The setting is unchanged.
- **Review of #57** (2026-10-17): the CHANGELOG's DuckDB line no longer claims duckdb-acl and acl-otel are at
  f8f3f4d (their main is on 7304f7b, acl-otel on ext-common v0.12.0); the checklist's contract stamps
  (`acl_checkout.sh` checks ACLC only), its gate (macOS on push only, `make wasm_eh` by hand, `live-image.yml`)
  and the community runner's consumer skips corrected; Auth0's `audience` added to the CHANGELOG.
- **The docs**:
  - `README.md` and the home page: the status lists named neither `tresor_login`, pipelines, variables nor
    generated parameters, and said nothing of wasm; the home page links the clients and pipelines pages;
  - `getting-started.md`: `DETACH` said "once secrets arrive, they leave the lookup" - they arrived in 004;
  - `security.md`: the services' logins now include a managed identity;
  - `protocol.md`'s conformance list gains `generators.test` (`TRESOR_CONFORMANCE_GENERATORS`, 029) - a
    description of the suite, not a protocol change;
  - `development.md`: the test-only extensions behind `TRESOR_TEST_HTTPFS` / `TRESOR_TEST_CONSUMERS`, the pin
    check, `web/` and `test/` in the layout.
  - Checked and current: `clients.md` (025), `pipelines.md` (026, 027), `web.md` (020), `reference-server.md`
    (029's generators, `cors_origins`), `security.md`'s certificates (030), `concepts.md`.
    `concepts.md`'s BigQuery paragraph was updated by #56: prefer `external_account_json`, never a service
    account key.
- **Specs hygiene.** Status lines agree with the README's index (007's and 020's in more words). Follow-ups done since are marked with the spec
  that did them: 001, 003 (Entra live), 004, 005, 006 (in part), 007, 009, 016 (variables, 018), 027 (both
  done in 027 itself), 031 (`ACL_COMMIT` ce1d417). 034's stays open: duckdb-acl #233 is not merged, and
  `ACL_COMMIT` is its branch commit 00375b8. 001 stays *accepted* (an architecture) and 017 *accepted* (the
  release waits for the tag); both now point here.

## Decided (2026-10-17)

- **wasm stays excluded** in `description.yml` and `distribution.yml` (`wasm_mvp`, `wasm_eh`,
  `wasm_threads`), the owner's decision: tresor's wasm needs duckdb-wasm on DuckDB 2.0 and the page's login
  (`tresor_web_login`, `@hugr-lab/tresor-web`), and is not in CI yet.

## Known gaps (no tests added now)

- **specs/025**, not covered by a sqllogictest (one connection, no concurrency): a logoff, DETACH or interrupt
  ending a kept catalog's wait for a login in progress; two ATTACHes or two `tresor_login` calls racing for
  one login; a login completing while a logoff runs; a lookup between a logoff and its removal from the store;
  a list fetched across a reset. Reviewed, not tested.
- **specs/029**: the client's side (`dynamic_params.test`) is checked against the fake, which serves
  descriptors it never generates. Generation through DuckDB runs only in `conformance/generators.test` and
  `reference_server/minted.test`, under `test_keycloak.sh` (docker). A claim generated under a delegation grant
  is tested in Go only.
- Also listed by their specs: https on DuckDB's HTTP client and a `307` not followed (020); acl's real sources
  in one target with tresor's (024, hugr-node's build); a cache hit read back after its type's extension loads
  (032); `rds` secrets and iceberg's table secret provider (033).

## Decided by the owner (2026-10-17)

- **`ACL_COMMIT`**: moved to duckdb-acl #233's merge commit 23a8b18 (tresor #58) - 034's follow-up done.
- **`enable_external_access`**: before the first release, `enable_external_access = false` stops tresor's own
  requests (its built-in client: the IdP and the service) as DuckDB's HTTP client is stopped - 023's follow-up,
  a spec of its own.
- **`@hugr-lab/tresor-web`**: not published with 0.1.0; it waits for duckdb-wasm on DuckDB 2.0, as wasm stays
  excluded from the distribution.
- **Where 0.1.0 goes**: duckdb/community-extensions; hugr lab's own extension repository as soon as it exists
  (not a condition of the release).

## Testing

Docs and metadata only: the docs build (`onBrokenLinks: throw`), `scripts/ci/check_docs_links.py`, yamllint on
the workflows, and CI.
