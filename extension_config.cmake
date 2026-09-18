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
