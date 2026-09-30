# This file is included by DuckDB's build system. It specifies which extension to load

# tresor itself, never linked (duckdb links only what duckdb_extension_statically_link() or
# STATICALLY_LINK_EXTENSIONS names, since DONT_LINK went away): the design's entry point is `ATTACH 'tresor:...'`, which loads an INSTALLED
# extension by the path's prefix (specs/001) - a test shell with tresor statically linked could never
# prove that, because the ATTACH type would already be registered.
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
        APPLY_PATCHES
        GIT_URL https://github.com/duckdb/duckdb-httpfs
        GIT_TAG 3f81d9749e538adc6e4882616fb2c9966e0cb0dd
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
