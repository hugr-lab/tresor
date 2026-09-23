# This file is included by DuckDB's build system. It specifies which extension to load

# tresor itself, DONT_LINK on purpose: the design's entry point is `ATTACH 'tresor:...'`, which
# loads an INSTALLED extension by the path's prefix (specs/001) - a test shell with tresor
# statically linked could never prove that, because the ATTACH type would already be registered.
# Tests load it the way production does: by build path, or installed from the build's local
# repository and pulled in by the ATTACH itself (test/sql/attach_loads_extension.test).
duckdb_extension_load(tresor
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    DONT_LINK
    LOAD_TESTS
)

# httpfs, for the tests only (specs/006): the s3 / gcs / r2 secret types, and the real REFRESH auto path
# a dynamic secret from the service goes through. Linked into the test shell at the commit (and with the
# patches) duckdb's own 2.0 tree pins in .github/config/extensions/httpfs.cmake - keep the two in step
# when the duckdb pin moves. It is not tresor's dependency: tresor never calls it.
duckdb_extension_load(httpfs
    APPLY_PATCHES
    GIT_URL https://github.com/duckdb/duckdb-httpfs
    GIT_TAG 0507d4ae4914ef30be5952bda0a547aa2b7ca981
)
