# tresor_sources.cmake - what tresor compiles and links, for its own build and for an extension that builds tresor
# into itself (specs/024: hugr-node's hugr_node, as it builds duckdb-acl in). Paths are this repository's
# (TRESOR_ROOT); duckdb's are the build's own source tree (CMAKE_SOURCE_DIR - the duckdb a build runs from), never
# this repository's submodule by path.
#
#   set(TRESOR_EMBEDDED ON)                            (an embedder only: no tresor entry point, tresor's version)
#   include(<tresor>/tresor_sources.cmake)             -> TRESOR_SOURCES, the include directories, OpenSSL
#   build_static_extension / build_loadable_extension  (the including build's own targets, TRESOR_SOURCES among
#                                                       their sources)
#   tresor_configure_targets(<static> <loadable>)      -> tresor's libraries on them
#
# Include it from the directory that creates the targets: tresor's compile definitions are properties of its
# sources (below), and a source's properties are seen by the targets of the directory that set them.

set(TRESOR_ROOT ${CMAKE_CURRENT_LIST_DIR})

include_directories(${TRESOR_ROOT}/src/include)
# Shared contracts and hook bases (hugr-lab/duckdb-ext-common, charter specs/001): header-only, so
# the submodule is an include path and nothing more.
include_directories(${TRESOR_ROOT}/duckdb-ext-common/hooks ${TRESOR_ROOT}/duckdb-ext-common/contracts)
# The OIDC client core (duckdb-ext-common oidc/, spec 003 there): compiled into tresor, under tresor's
# namespace (charter R13), with the bundled httplib and yyjson of the build's duckdb tree. It is tresor's
# whole transport - the IdP's flows and the service's API alike (specs/002).
include(${TRESOR_ROOT}/duckdb-ext-common/oidc/oidc.cmake)
include_directories(${DUCKDB_EXT_COMMON_OIDC_INCLUDE} ${CMAKE_SOURCE_DIR}/third_party/httplib
                    ${CMAKE_SOURCE_DIR}/third_party/yyjson/include)
# The keychain module (duckdb-ext-common keychain/, spec 010 there): a person's refresh token in the OS
# credential store, never a file (specs/012). Compiled in, under tresor's namespace.
include(${TRESOR_ROOT}/duckdb-ext-common/keychain/keychain.cmake)
include_directories(${DUCKDB_EXT_COMMON_KEYCHAIN_INCLUDE})
set(TRESOR_KEYCHAIN_LIBS ${DUCKDB_EXT_COMMON_KEYCHAIN_LIBS})

set(TRESOR_SOURCES
    ${TRESOR_ROOT}/src/tresor_extension.cpp
    ${TRESOR_ROOT}/src/tresor_events.cpp
    ${TRESOR_ROOT}/src/tresor_actor.cpp
    ${TRESOR_ROOT}/src/tresor_browser.cpp
    ${TRESOR_ROOT}/src/tresor_catalog.cpp
    ${TRESOR_ROOT}/src/tresor_login.cpp
    ${TRESOR_ROOT}/src/tresor_manage.cpp
    ${TRESOR_ROOT}/src/tresor_secret.cpp
    ${TRESOR_ROOT}/src/tresor_secrets.cpp
    ${TRESOR_ROOT}/src/tresor_storage.cpp
    ${TRESOR_ROOT}/src/tresor_session.cpp
    ${TRESOR_ROOT}/src/tresor_whoami.cpp
    ${TRESOR_ROOT}/src/tresor_remember.cpp
    ${TRESOR_ROOT}/src/tresor_http.cpp
    ${TRESOR_ROOT}/src/tresor_credentials.cpp
    ${TRESOR_ROOT}/src/tresor_logoff.cpp
    ${TRESOR_ROOT}/src/tresor_web_login.cpp
    ${TRESOR_ROOT}/src/tresor_login_function.cpp
    ${TRESOR_ROOT}/src/tresor_pending.cpp
    ${TRESOR_ROOT}/src/tresor_act.cpp
    ${TRESOR_ROOT}/src/tresor_variables.cpp
    ${DUCKDB_EXT_COMMON_OIDC_SOURCES}
    ${DUCKDB_EXT_COMMON_KEYCHAIN_SOURCES})

# The modules' namespace is the consumer's (duckdb-ext-common charter R13): `duckdb::tresor::oidc`,
# `duckdb::tresor::keychain`. On tresor's sources, not on a target: an embedder's one target also compiles
# duckdb-acl, whose copy of the OIDC core is `duckdb::acl::oidc` - a target-wide definition would give one of the
# two the other's names. A source's definitions come after its target's on the command line, so these win on
# tresor's sources even where an embedder's target defines another namespace.
set_property(SOURCE ${TRESOR_SOURCES} APPEND PROPERTY COMPILE_DEFINITIONS DUCKDB_EXT_COMMON_OIDC_NAMESPACE=tresor
             DUCKDB_EXT_COMMON_OIDC_TLS=1 DUCKDB_EXT_COMMON_KEYCHAIN_NAMESPACE=tresor)

# Built into another extension (specs/024): tresor's entry point and TresorExtension are not compiled (the
# embedder's entry is the one), and tresor_version() answers tresor's own version - duckdb defines
# EXT_VERSION_<NAME> for the extension it builds, which is then the embedder's.
if(TRESOR_EMBEDDED)
    set_property(SOURCE ${TRESOR_SOURCES} APPEND PROPERTY COMPILE_DEFINITIONS TRESOR_EMBEDDED)
    set(TRESOR_EMBEDDED_VERSION "")
    if(COMMAND duckdb_extension_generate_version)
        duckdb_extension_generate_version(TRESOR_EMBEDDED_VERSION ${TRESOR_ROOT})
    endif()
    if(NOT "${TRESOR_EMBEDDED_VERSION}" STREQUAL "")
        set_property(SOURCE ${TRESOR_ROOT}/src/tresor_extension.cpp APPEND PROPERTY COMPILE_DEFINITIONS
                     TRESOR_VERSION="${TRESOR_EMBEDDED_VERSION}")
    endif()
endif()

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

# Built in beside duckdb-acl (acl_sources.cmake, ACL_ROOT): one directory, so whichever duckdb-ext-common the
# include directories name first serves its headers - the OIDC core's, the contracts - to both halves. They must be
# the same files, not only the same contract stamps (oidc_core.hpp carries none): refused otherwise.
function(tresor_check_shared_headers)
    if(NOT DEFINED ACL_ROOT OR NOT EXISTS "${ACL_ROOT}/duckdb-ext-common")
        return()
    endif()
    file(GLOB shared RELATIVE "${TRESOR_ROOT}/duckdb-ext-common" "${TRESOR_ROOT}/duckdb-ext-common/oidc/include/*"
         "${TRESOR_ROOT}/duckdb-ext-common/contracts/*")
    foreach(header ${shared})
        if(EXISTS "${ACL_ROOT}/duckdb-ext-common/${header}")
            file(SHA256 "${TRESOR_ROOT}/duckdb-ext-common/${header}" ours)
            file(SHA256 "${ACL_ROOT}/duckdb-ext-common/${header}" theirs)
            if(NOT ours STREQUAL theirs)
                message(FATAL_ERROR "tresor and duckdb-acl, built into one extension, need the same duckdb-ext-common: "
                                    "${header} differs (pin both submodules to one commit)")
            endif()
        endif()
    endforeach()
endfunction()

# tresor's libraries, on the targets the including build made
function(tresor_configure_targets)
    tresor_check_shared_headers()
    foreach(target ${ARGN})
        target_link_libraries(${target} OpenSSL::SSL OpenSSL::Crypto ${TRESOR_KEYCHAIN_LIBS})
        # the bundled httplib reads the OS trust store: the Security framework on macOS; winsock and
        # crypt32 (OpenSSL's RNG) on Windows, which MinGW does not pick up from httplib's pragmas
        if(APPLE)
            target_link_libraries(${target} "-framework Security" "-framework CoreFoundation")
        endif()
        if(WIN32)
            target_link_libraries(${target} ws2_32 crypt32 shell32)
        endif()
        if(TRESOR_EMBEDDED)
            # the embedder's own sources see tresor_extension.hpp as tresor's do
            target_compile_definitions(${target} PRIVATE TRESOR_EMBEDDED)
        endif()
    endforeach()
endfunction()
