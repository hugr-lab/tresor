# This file is included by DuckDB's build system. It specifies which extension to load

# Windows with clang-cl (extension-ci-tools since #428) and vcpkg ports built by MSVC (OpenSSL here): clang-cl
# pools a string literal into a COMDAT the linker may resolve to MSVC's copy of the same literal, aligned less
# than clang-cl's code assumes - an aligned load of it faults before main, coming and going with the layout of
# .rdata (duckdb/extension-ci-tools#430; duckdb-acl spec 106). /GF- turns string pooling off for what clang-cl
# compiles, so every pooled literal the link selects is an MSVC one. Included at the top level before duckdb adds
# src/, so it reaches duckdb's own objects too. Nothing under cl, MinGW or any other platform (specs/022).
if(MSVC AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(/GF-)
endif()

# tresor itself, never linked (duckdb links only what duckdb_extension_statically_link() or
# STATICALLY_LINK_EXTENSIONS names, since DONT_LINK went away): the design's entry point is
# `ATTACH 'tresor:...'`, which loads an INSTALLED extension by the path's prefix (specs/001) - a test
# shell with tresor statically linked could never prove that, because the ATTACH type would already be
# registered.
# Tests load it the way production does: by build path, or installed from the build's local
# repository and pulled in by the ATTACH itself (test/sql/attach_loads_extension.test).
duckdb_extension_load(tresor
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    LOAD_TESTS
)

# httpfs, for the tests only (specs/006): the s3 / gcs / r2 / aws secret types, and the real REFRESH auto
# path a dynamic secret from the service goes through. Opt-in (TRESOR_TEST_HTTPFS=1, set by ci.yml's build
# jobs): the distribution / community builds use this file too, and must not compile a test-only extension
# whose patches follow duckdb's branch head. At the commit (and with the patches) duckdb's own 2.0 tree pins
# in .github/config/extensions/httpfs.cmake - move both with the duckdb pin. tresor never calls httpfs.
if(DEFINED ENV{TRESOR_TEST_HTTPFS} AND "$ENV{TRESOR_TEST_HTTPFS}" STREQUAL "1")
    duckdb_extension_load(httpfs
        GIT_URL https://github.com/duckdb/duckdb-httpfs
        GIT_TAG 77392a72077a85897db2519fae11e2c0da972b8a
    )
    duckdb_extension_statically_link(httpfs)
endif()

# acl_stub, for the tests only (specs/008): duckdb-acl's side of the acl_connection contract - sessions opened
# and closed for tresor's observer, a session published on a connection's statements - so the actor path is
# tested without building duckdb-acl (arrow and all). Same opt-in as httpfs; never in a distribution build.
if(DEFINED ENV{TRESOR_TEST_HTTPFS} AND "$ENV{TRESOR_TEST_HTTPFS}" STREQUAL "1")
    duckdb_extension_load(acl_stub
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/test/extension/acl_stub
    )
    duckdb_extension_statically_link(acl_stub)
endif()

# typed_secret_stub, for the tests only (specs/032): secret types of an extension's own classes, cast to them as
# bigquery casts to BigquerySecret - what tresor serves must be of the class the type's deserializer makes. Same
# opt-in as httpfs; never in a distribution build.
if(DEFINED ENV{TRESOR_TEST_HTTPFS} AND "$ENV{TRESOR_TEST_HTTPFS}" STREQUAL "1")
    duckdb_extension_load(typed_secret_stub
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/test/extension/typed_secret_stub
    )
    duckdb_extension_statically_link(typed_secret_stub)
endif()

# the consumers, for the tests only (specs/033): a secret tresor serves must reach the extension that uses it -
# postgres_scanner's ATTACH, iceberg's REST catalog (with avro, which iceberg loads at its own load). Opt-in
# (TRESOR_TEST_CONSUMERS=1, set by ci.yml's consumers job, beside TRESOR_TEST_HTTPFS=1 - iceberg talks HTTP through
# httpfs): their vcpkg dependencies (libpq, aws-sdk-cpp, roaring, avro-c, ...) enter the merged manifest only with
# it, so the distribution build and the other jobs never build them. iceberg and avro are linked into the test
# build, postgres_scanner is not (below). At the commits (and with the patches) duckdb's own 2.0 tree pins in
# .github/config/extensions/{postgres_scanner,iceberg,avro}.cmake - move them with the duckdb pin
# (scripts/ci/check_extension_pins.sh checks every GIT_TAG here against duckdb's).
if(DEFINED ENV{TRESOR_TEST_CONSUMERS} AND "$ENV{TRESOR_TEST_CONSUMERS}" STREQUAL "1")
    if(NOT (DEFINED ENV{TRESOR_TEST_HTTPFS} AND "$ENV{TRESOR_TEST_HTTPFS}" STREQUAL "1"))
        message(FATAL_ERROR "TRESOR_TEST_CONSUMERS=1 needs TRESOR_TEST_HTTPFS=1: iceberg talks HTTP through httpfs, "
                            "and test/sql/consumers/httpfs.test is httpfs's")
    endif()
    # the same platform guards as duckdb's own configs
    # never linked: its CMakeLists links libpq into the loadable extension only - tests load it by build path
    if(NOT MINGW AND NOT ${WASM_ENABLED})
        duckdb_extension_load(postgres_scanner
            GIT_URL https://github.com/duckdb/duckdb-postgres
            GIT_TAG c0f5a3c0c4b68b02afbf669d36d7f0e503985c88
            SUBMODULES database-connector
        )
    endif()
    if(NOT MINGW)
        duckdb_extension_load(avro
            GIT_URL https://github.com/duckdb/duckdb-avro
            GIT_TAG 758fb6063cbb6da49b2e1c16c4044cfcafefc52f
            SUBMODULES "third_party/avro-c"
            APPLY_PATCHES
        )
        duckdb_extension_statically_link(avro)
        duckdb_extension_load(iceberg
            GIT_URL https://github.com/duckdb/duckdb-iceberg
            GIT_TAG 4c0c0874c48ec82a3e29910554891d04bcc0e988
        )
        duckdb_extension_statically_link(iceberg)
    endif()
endif()

# tresor_embedder, for the tests only (specs/024): an extension that builds tresor into itself through
# tresor_sources.cmake and LoadTresorCore, as hugr-node's hugr_node does. Same opt-in; never linked (like tresor,
# it is loaded by build path - test/sql/embedded.test), never in a distribution build.
if(DEFINED ENV{TRESOR_TEST_HTTPFS} AND "$ENV{TRESOR_TEST_HTTPFS}" STREQUAL "1")
    duckdb_extension_load(tresor_embedder
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/test/extension/tresor_embedder
    )
endif()

# duckdb-acl itself, for the actor's end-to-end test only (specs/008, test/acl/actor.sql): built here, against
# this tree's duckdb, so it loads into the test build exactly (acl's own distribution artifacts are built at
# its branch's head, not at the pinned commit). TRESOR_TEST_ACL_DIR is a checkout of duckdb-acl at the commit
# scripts/ci/acl_checkout.sh pins, with its duckdb-ext-common submodule and a `duckdb` link to ours; lean
# (ACL_NO_FLIGHT, ACL_NO_QUACK_EMBED: no arrow, no quack - the actor needs neither). Never linked: a test
# shell with acl linked would run every other test under acl's rewriter.
if(DEFINED ENV{TRESOR_TEST_ACL_DIR} AND NOT "$ENV{TRESOR_TEST_ACL_DIR}" STREQUAL "")
    duckdb_extension_load(acl
        SOURCE_DIR $ENV{TRESOR_TEST_ACL_DIR}
    )
endif()
