cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME tresor)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

set(CMAKE_CXX_STANDARD "17" CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# the sources, include directories, OpenSSL and the duckdb-ext-common modules - shared with an extension that
# builds tresor into itself (specs/024)
include(${CMAKE_CURRENT_LIST_DIR}/tresor_sources.cmake)

build_static_extension(${TARGET_NAME} ${TRESOR_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${TRESOR_SOURCES})
tresor_configure_targets(${EXTENSION_NAME} ${LOADABLE_EXTENSION_NAME})

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
