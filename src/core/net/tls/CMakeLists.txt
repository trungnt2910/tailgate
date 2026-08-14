tailgate_add_library(
    tailgate_core_net_tls
    STATIC
    TlsStream.cpp
    TlsWriteProgress.h
)
target_include_directories(
    tailgate_core_net_tls
    PRIVATE "${PROJECT_SOURCE_DIR}/src/core"
)
target_link_libraries(
    tailgate_core_net_tls
    PUBLIC
        tailgate_core_base
    PRIVATE
        MbedTLS::mbedtls
        tailgate_core_crypto
)
