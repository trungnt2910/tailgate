include(FetchContent)

set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build dependencies as static libraries" FORCE)
set(TAILGATE_ORIGINAL_C_FLAGS "${CMAKE_C_FLAGS}")
set(TAILGATE_ORIGINAL_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
string(APPEND CMAKE_C_FLAGS " ${TAILGATE_THIRD_PARTY_COMPILE_FLAGS}")
string(APPEND CMAKE_CXX_FLAGS " ${TAILGATE_THIRD_PARTY_COMPILE_FLAGS}")

FetchContent_Declare(
    Sodium
    GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
    GIT_TAG e5b985ad0dd235d8c4307ea3a385b45e76c74c6a
)
set(SODIUM_DISABLE_TESTS ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(Sodium)

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    MbedTLS
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG mbedtls-4.1.0
)
FetchContent_MakeAvailable(MbedTLS)

set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
    NlohmannJson
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.12.0
)
FetchContent_MakeAvailable(NlohmannJson)

if(TAILGATE_BUILD_FRONTEND OR TAILGATE_BUILD_TESTS)
    set(CLI11_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(CLI11_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
        CLI11
        GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
        GIT_TAG v2.6.2
    )
    FetchContent_MakeAvailable(CLI11)
endif()

if(TAILGATE_BUILD_TESTS)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    FetchContent_Declare(
        GoogleTest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.17.0
    )
    FetchContent_MakeAvailable(GoogleTest)
endif()

FetchContent_Declare(
    WireGuardLwip
    GIT_REPOSITORY https://github.com/smartalock/wireguard-lwip.git
    GIT_TAG f0d0ca5153b798354087610ffac5b5efd2312d27
    GIT_SHALLOW TRUE
    SOURCE_SUBDIR src
)
FetchContent_MakeAvailable(WireGuardLwip)

# wireguard-lwip intentionally exposes source-level integration rather than a CMake target.
# Keep that upstream file-list dependency isolated here instead of leaking it into Core.
tailgate_add_third_party_library(
    tailgate_wireguard_crypto
    STATIC
    ${wireguardlwip_SOURCE_DIR}/src/crypto.c
    ${wireguardlwip_SOURCE_DIR}/src/crypto/refc/blake2s.c
    ${wireguardlwip_SOURCE_DIR}/src/crypto/refc/chacha20.c
    ${wireguardlwip_SOURCE_DIR}/src/crypto/refc/chacha20poly1305.c
    ${wireguardlwip_SOURCE_DIR}/src/crypto/refc/poly1305-donna.c
    ${wireguardlwip_SOURCE_DIR}/src/crypto/refc/x25519.c
    ${wireguardlwip_SOURCE_DIR}/src/wireguard.c
    ${PROJECT_SOURCE_DIR}/src/core/WireguardPlatform.cpp
)
target_include_directories(
    tailgate_wireguard_crypto
    PUBLIC
    ${wireguardlwip_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/src/core/wireguard_compat
)
target_link_libraries(tailgate_wireguard_crypto PRIVATE sodium)

set(CMAKE_C_FLAGS "${TAILGATE_ORIGINAL_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${TAILGATE_ORIGINAL_CXX_FLAGS}")
unset(TAILGATE_ORIGINAL_C_FLAGS)
unset(TAILGATE_ORIGINAL_CXX_FLAGS)
