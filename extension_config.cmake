# This file is included by DuckDB's build system. It specifies which extension to load

# tresor itself. Statically linked into the test shell (its Load has no gates that could fail a
# database open), and built as a loadable too - the loadable is what scripts/ci/smoke_load.sh proves:
# installed into an isolated extension directory, an `ATTACH 'tresor:...'` must load it by prefix.
duckdb_extension_load(tresor
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
    LOAD_TESTS
)
