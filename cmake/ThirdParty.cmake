include("${CMAKE_CURRENT_LIST_DIR}/GetCPM.cmake")

set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build dependencies as static libraries" FORCE)
set(TAILGATE_ORIGINAL_C_FLAGS "${CMAKE_C_FLAGS}")
set(TAILGATE_ORIGINAL_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
string(APPEND CMAKE_C_FLAGS " ${TAILGATE_THIRD_PARTY_COMPILE_FLAGS}")
string(APPEND CMAKE_CXX_FLAGS " ${TAILGATE_THIRD_PARTY_COMPILE_FLAGS}")

CPMAddPackage(
    NAME Sodium
    GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
    GIT_TAG e5b985ad0dd235d8c4307ea3a385b45e76c74c6a
    OPTIONS "SODIUM_DISABLE_TESTS ON"
)

# Avoid git for MbedTLS
# The source repository has large submodules and requires other third-party tools for codegen.
CPMAddPackage(
    NAME MbedTLS
    VERSION 4.1.0
    URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-4.1.0/mbedtls-4.1.0.tar.bz2
    URL_HASH SHA256=377a09cf8eb81b5fb2707045e5522d5489d3309fed5006c9874e60558fc81d10
    OPTIONS "ENABLE_PROGRAMS OFF" "ENABLE_TESTING OFF"
)

CPMAddPackage(
    NAME NlohmannJson
    VERSION 3.12.0
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.12.0
    OPTIONS "JSON_BuildTests OFF"
)

CPMAddPackage(
    NAME Zint
    VERSION 2.16.0
    GIT_REPOSITORY https://github.com/zint/zint.git
    GIT_TAG 2.16.0
    GIT_SHALLOW TRUE
    OPTIONS
        "ZINT_SHARED OFF"
        "ZINT_STATIC ON"
        "ZINT_FRONTEND OFF"
        "ZINT_USE_GS1SE OFF"
        "ZINT_USE_PNG OFF"
        "ZINT_USE_QT OFF"
        "ZINT_TEST OFF"
        "ZINT_UNINSTALL OFF"
)
# LLVM 22 miscompiles Zint's dynamic stack allocations for 32-bit Windows ARM at optimized
# levels by using condition flags clobbered by __chkstk. Keep Zint unoptimized until the
# toolchain issue is fixed.
# See: https://github.com/llvm/llvm-project/issues/210939
target_compile_options(zint-static PRIVATE -O0)

CPMAddPackage(
    NAME CLI11
    VERSION 2.6.2
    GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
    GIT_TAG v2.6.2
    OPTIONS "CLI11_BUILD_TESTS OFF" "CLI11_BUILD_EXAMPLES OFF"
)

string(
    CONCAT
    TAILGATE_BOOST_URL
    "https://github.com/boostorg/boost/releases/download/boost-1.91.0-1/"
    "boost-1.91.0-1-cmake.tar.xz"
)
CPMAddPackage(
    NAME Boost
    VERSION 1.91.0
    URL "${TAILGATE_BOOST_URL}"
    URL_HASH SHA256=cc5dc5006ecbdf0051f90979be31b4eee5987d9ae14ae9fb9c03cfa43fa3cdad
    DOWNLOAD_EXTRACT_TIMESTAMP ON
    EXCLUDE_FROM_ALL
    OPTIONS "BOOST_INCLUDE_LIBRARIES algorithm"
)
unset(TAILGATE_BOOST_URL)

if(TAILGATE_BUILD_UWP)
    CPMAddPackage(
        NAME BoostExtDi
        VERSION 1.3.2
        GIT_REPOSITORY https://github.com/boost-ext/di.git
        GIT_TAG v1.3.2
        GIT_SHALLOW TRUE
        OPTIONS "BOOST_DI_OPT_BUILD_TESTS OFF" "BOOST_DI_OPT_BUILD_EXAMPLES OFF"
    )
endif()

if(TAILGATE_BUILD_TESTS)
    CPMAddPackage(
        NAME GoogleTest
        VERSION 1.17.0
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.17.0
        OPTIONS "INSTALL_GTEST OFF"
    )
endif()

CPMAddPackage(
    NAME WireGuardLwip
    GIT_REPOSITORY https://github.com/smartalock/wireguard-lwip.git
    GIT_TAG f0d0ca5153b798354087610ffac5b5efd2312d27
    GIT_SHALLOW TRUE
    SOURCE_SUBDIR src
)

# wireguard-lwip intentionally exposes source-level integration rather than a CMake target.
# Keep that upstream file-list dependency isolated here instead of leaking it into Core.
tailgate_add_third_party_library(
    tailgate_wireguard_crypto
    STATIC
    ${WireGuardLwip_SOURCE_DIR}/src/crypto.c
    ${WireGuardLwip_SOURCE_DIR}/src/crypto/refc/blake2s.c
    ${WireGuardLwip_SOURCE_DIR}/src/crypto/refc/chacha20.c
    ${WireGuardLwip_SOURCE_DIR}/src/crypto/refc/chacha20poly1305.c
    ${WireGuardLwip_SOURCE_DIR}/src/crypto/refc/poly1305-donna.c
    ${WireGuardLwip_SOURCE_DIR}/src/crypto/refc/x25519.c
    ${WireGuardLwip_SOURCE_DIR}/src/wireguard.c
    ${PROJECT_SOURCE_DIR}/src/core/WireguardPlatform.cpp
)
target_include_directories(
    tailgate_wireguard_crypto
    PUBLIC
    ${WireGuardLwip_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/src/core/wireguard_compat
)
target_link_libraries(tailgate_wireguard_crypto PRIVATE sodium)

set(CMAKE_C_FLAGS "${TAILGATE_ORIGINAL_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${TAILGATE_ORIGINAL_CXX_FLAGS}")
unset(TAILGATE_ORIGINAL_C_FLAGS)
unset(TAILGATE_ORIGINAL_CXX_FLAGS)
