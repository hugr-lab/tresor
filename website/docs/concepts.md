---
sidebar_position: 3
title: Concepts
---

# Concepts

## The attached catalog is three things

`ATTACH 'tresor:…' AS corp` creates one name with three roles:

1. **A secret storage named `corp`** in DuckDB's secret manager. Its secrets take part in every
   lookup; `CREATE PERSISTENT SECRET … IN corp` stores into the service and `DROP PERSISTENT SECRET …
   FROM corp` deletes there. `SET default_secret_storage = 'corp'` makes the service the default for
   persistent secrets.
2. **A catalog of functions** — `corp.secrets()`, `corp.whoami()`, `corp.grants(…)`,
   `corp.delegations(…)`, `corp.annotate_secret(…)`, `corp.grant_secret(…)`, `corp.add_delegation(…)` —
   the view and the management surface.
3. **A login.** The identity the attach established is what every call to the service carries.

Several services can be attached at once; each is its own storage and its own catalog.

## Lookup

DuckDB picks a secret by how well its scope matches the path in hand. tresor keeps the list of
secrets your role may use (names, types, scopes — no material) and answers DuckDB's lookup from it;
the **material is fetched only when a secret matches**, and cached until it expires. Secrets the
service marks *dynamic* are generated per request with an expiry — short-lived credentials — and S3
secrets among them are refreshed through httpfs's own `REFRESH auto` when they run out.

## What your role may do

The service decides, per secret, which of these verbs you hold — and shows them in
`corp.secrets()`:

| Verb | Meaning |
| --- | --- |
| `create` | create new secrets (service-wide, possibly limited to name patterns) |
| `use` | receive the material yourself |
| `update` / `delete` | replace or remove |
| `annotate` | describe |
| `grant` | give or take verbs from others |
| `delegate` | set up delegation |

## Delegation

A server — a DuckDB node behind a gateway, a data platform — sometimes works **on behalf of** a
user: reading an API with the user's rights, writing to the user's area of object storage. A
secret is **not delegated** unless the service has a rule for it. A delegation rule says which
servers may act, for which users, how:

- **`user`** — the service issues a credential of the user's own (a tagged STS session, a temporary
  database user, a token on the user's behalf): the resource sees the person.
- **`shared`** — the server receives a shared secret, only to act for that user, and every use is
  audited under the user's name. The user needs no `use` verb: they can **use a secret without ever
  seeing it**, which is only possible through a server.

A server acting for a user never adds its own authority: every call carries the user's identity,
and the service checks the user's rights, the rule, and that the server may act for users at all.
