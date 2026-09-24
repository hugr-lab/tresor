cmake_minimum_required(VERSION 3.5)

# acl_stub: duckdb-acl's side of the acl_connection contract, for tresor's tests only (specs/008) -
# linked into the test build beside httpfs (TRESOR_TEST_HTTPFS=1, extension_config.cmake), never shipped.
set(TARGET_NAME acl_stub)
set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

set(CMAKE_CXX_STANDARD "17" CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(src/include ${CMAKE_CURRENT_LIST_DIR}/../../../duckdb-ext-common/contracts
                    ${CMAKE_CURRENT_LIST_DIR}/../../../duckdb-ext-common/hooks)

build_static_extension(${TARGET_NAME} src/acl_stub_extension.cpp)
build_loadable_extension(${TARGET_NAME} " " src/acl_stub_extension.cpp)

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
