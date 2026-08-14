add_subdirectory(acme)

tailgate_add_library(
    tailgate_core_serve
    STATIC
    FunnelConfig.cpp
    HandshakeLimiter.cpp
    PeerApiIngress.cpp
)
target_include_directories(
    tailgate_core_serve
    PRIVATE "${PROJECT_SOURCE_DIR}/src/core"
)
target_link_libraries(
    tailgate_core_serve
    PUBLIC
        tailgate_core_base
        tailgate_core_control_client
    PRIVATE
        Boost::algorithm
        MbedTLS::mbedtls
        tailgate_core_crypto
)
