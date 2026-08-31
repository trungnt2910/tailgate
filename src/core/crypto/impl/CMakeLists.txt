tailgate_add_library(
    tailgate_core_crypto_impl
    STATIC
    MbedTlsCertificate.cpp
    RandomImpl.cpp
)
target_include_directories(
    tailgate_core_crypto_impl
    PRIVATE "${PROJECT_SOURCE_DIR}/src/core"
)
target_link_libraries(
    tailgate_core_crypto_impl
    PUBLIC tailgate_core_crypto
    PRIVATE
        MbedTLS::mbedtls
        nlohmann_json::nlohmann_json
        sodium
)
