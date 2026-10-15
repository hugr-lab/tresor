cmake_minimum_required(VERSION 3.5)

# typed_secret_stub: secret types of an extension's own classes, for tresor's tests only (specs/032) -
# linked into the test build beside httpfs (TRESOR_TEST_HTTPFS=1, extension_config.cmake), never shipped.
set(TARGET_NAME typed_secret_stub)
set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

set(CMAKE_CXX_STANDARD "17" CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(src/include)

build_static_extension(${TARGET_NAME} src/typed_secret_stub_extension.cpp)
build_loadable_extension(${TARGET_NAME} " " src/typed_secret_stub_extension.cpp)

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
