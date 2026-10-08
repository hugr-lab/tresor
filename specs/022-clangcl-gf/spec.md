# Spec 022: /GF- for clang-cl on Windows - MSVC-built ports and pooled literals

- **Status**: implemented
- **Date**: 2026-10-08
- **Author**: hugr lab
- **Asked by**: the owner, after duckdb-acl's heads-up (its spec 106; acl-otel's spec 017)

## Summary

extension-ci-tools builds the Windows extension with clang-cl (#428), while the vcpkg ports - OpenSSL for
tresor - are built by MSVC. clang-cl pools string literals into COMDATs; the linker may pick MSVC's copy of the
same literal, aligned less than clang-cl's code assumes, and an aligned SSE load of it faults before main
(duckdb/extension-ci-tools#430). `extension_config.cmake` now adds `/GF-` (no string pooling) for clang-cl
under MSVC, at the top level, so duckdb's own objects get it too. Nothing changes under cl, MinGW or any other
platform.

## Context

- ci-tools #431 (2026-10-08) briefly built the ports with clang-cl too; its `.rc` handling broke ports that ship
  a `version.rc` (protobuf in acl-otel). tresor's Distribution run during it was green on every platform - static
  OpenSSL builds through its own Configure/nmake - and is being reverted upstream.
- That run cannot show #430 either way (the ports were clang-cl as well): the check is a Distribution run after
  the revert, with MSVC-built ports again.

## Testing

- Distribution on main after the revert of #431: windows_amd64 (clang-cl, MSVC ports) builds and its
  artifact loads.
