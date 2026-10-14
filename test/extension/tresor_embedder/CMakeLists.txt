cmake_minimum_required(VERSION 3.5)

# tresor_embedder: an extension that builds tresor into itself the way hugr-node's hugr_node does (specs/024) -
# tresor_sources.cmake with TRESOR_EMBEDDED, its own entry point calling LoadTresorCore. For tresor's tests only:
# built beside acl_stub (TRESOR_TEST_HTTPFS=1, extension_config.cmake), never linked into the test shell (the
# tests load it by build path), never shipped.
set(TARGET_NAME tresor_embedder)
set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

set(CMAKE_CXX_STANDARD "17" CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(TRESOR_EMBEDDED ON)
include(${CMAKE_CURRENT_LIST_DIR}/../../../tresor_sources.cmake)

set(EMBEDDER_SOURCES src/tresor_embedder_extension.cpp ${TRESOR_SOURCES})
build_static_extension(${TARGET_NAME} ${EMBEDDER_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EMBEDDER_SOURCES})
tresor_configure_targets(${EXTENSION_NAME} ${LOADABLE_EXTENSION_NAME})

# what hugr_node's target also carries: duckdb-acl's acl_configure_targets defines the OIDC core's namespace on the
# whole target (`acl`). tresor's sources must still be compiled as `tresor` - its source-level definition wins.
foreach(target ${EXTENSION_NAME} ${LOADABLE_EXTENSION_NAME})
    target_compile_definitions(${target} PRIVATE DUCKDB_EXT_COMMON_OIDC_NAMESPACE=embedder)
endforeach()

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
