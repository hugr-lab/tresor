# Spec NNN: <feature name>

- **Status**: draft | accepted | implemented | superseded by NNN
- **Date**: YYYY-MM-DD
- **Author**: <who>

## Summary

One paragraph: what this feature is and why, in plain language.

## Problem

What is missing or wrong today, and who is affected. Concrete examples of queries/workloads that do
not work yet.

## Design

The chosen approach. Cover, as applicable: SQL surface (ATTACH options, catalog functions,
secret types/providers), the duckdb seams touched (secret storage, storage extension, file system),
the protocol requests and their HTTP semantics (and whether `website/docs/protocol.md` changes),
what crosses into duckdb-ext-common or duckdb-acl, and version-pin implications.

## Enforcement & security

Fail-closed behavior, trust assumptions, what happens across a version mismatch.

## Testing

How it is proven: sqllogictest cases, C++ tests, integration scenarios against a real SQL Server.

## Alternatives considered

Options rejected and why (briefly).

## Follow-ups
