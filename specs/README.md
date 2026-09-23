# Specs

One **lightweight spec per change** — deliberately not full spec-kit: no plan/tasks machinery, just a
short, honest document so decisions are written down and reviewable.

## Process

1. Before (or alongside) a change, create `specs/NNN-slug/spec.md` from `TEMPLATE.md` (`NNN` = next
   zero-padded number, `slug` = short kebab-case).
2. A change that spans repositories (duckdb-ext-common, duckdb-acl, acl-otel) is specced on both sides,
   each part in its own repository, each referencing the other.
3. Keep the spec current; set `Status: implemented` when it lands; reference it in the commit/PR.
4. Supersede, don't rewrite: a reversed decision gets a new spec, the old one `superseded by NNN`.

Research and thinking-out-loud live in the local, gitignored `design/` folder.

## Index

| Spec | Title | Status |
| --- | --- | --- |
| [001](001-architecture/spec.md) | attach a secrets service, one OIDC login, role-based secrets | accepted |
| [002](002-attach-login/spec.md) | attach — discovery, one OIDC login (people and services), `corp.whoami()` | implemented |
| [003](003-reference-server/spec.md) | the reference server — duckdb-secrets/1 in Go, Keycloak end to end, the conformance suite | implemented |
| [004](004-secret-storage/spec.md) | the secret storage — the service's secrets in DuckDB's lookup, `corp.secrets()` | draft |
