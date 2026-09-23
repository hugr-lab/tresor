cmake_minimum_required(VERSION 3.5)

# Set extension name here
set(TARGET_NAME tresor)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

set(CMAKE_CXX_STANDARD "17" CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(src/include)
# Shared contracts and hook bases (hugr-lab/duckdb-ext-common, charter specs/001): header-only, so
# the submodule is an include path and nothing more.
include_directories(duckdb-ext-common/hooks duckdb-ext-common/contracts)
# The OIDC client core (duckdb-ext-common oidc/, spec 003 there): compiled into tresor, under tresor's
# namespace (charter R13), with the bundled httplib and yyjson of our own duckdb tree. It is tresor's
# whole transport - the IdP's flows and the service's API alike (specs/002).
include(duckdb-ext-common/oidc/oidc.cmake)
include_directories(${DUCKDB_EXT_COMMON_OIDC_INCLUDE} duckdb/third_party/httplib duckdb/third_party/yyjson/include)

set(EXTENSION_SOURCES
    src/tresor_extension.cpp
    src/tresor_browser.cpp
    src/tresor_catalog.cpp
    src/tresor_login.cpp
    src/tresor_secret.cpp
    src/tresor_session.cpp
    src/tresor_whoami.cpp
    ${DUCKDB_EXT_COMMON_OIDC_SOURCES})

# https is not optional: the protocol is https, and so is every identity provider. OpenSSL comes from
# vcpkg (vcpkg.json), static, as in duckdb-acl; the machine's own prefixes are kept out of the search
# so the artifact never depends on a homebrew library.
set(OPENSSL_USE_STATIC_LIBS ON)
foreach(system_prefix "/opt/homebrew" "/usr/local")
    if(EXISTS "${system_prefix}")
        list(APPEND CMAKE_IGNORE_PREFIX_PATH "${system_prefix}")
    endif()
endforeach()
find_package(OpenSSL REQUIRED)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

foreach(target ${EXTENSION_NAME} ${LOADABLE_EXTENSION_NAME})
    target_compile_definitions(${target} PRIVATE DUCKDB_EXT_COMMON_OIDC_NAMESPACE=tresor DUCKDB_EXT_COMMON_OIDC_TLS=1)
    target_link_libraries(${target} OpenSSL::SSL OpenSSL::Crypto)
    # the bundled httplib reads the OS trust store: the Security framework on macOS; winsock and
    # crypt32 (OpenSSL's RNG) on Windows, which MinGW does not pick up from httplib's pragmas
    if(APPLE)
        target_link_libraries(${target} "-framework Security" "-framework CoreFoundation")
    endif()
    if(WIN32)
        target_link_libraries(${target} ws2_32 crypt32 shell32)
    endif()
endforeach()

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
