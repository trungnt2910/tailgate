tailgate_add_library(
    tailgate_core_serve_acme
    STATIC
    Client.cpp
    Crypto.cpp
)
target_include_directories(
    tailgate_core_serve_acme
    PRIVATE "${PROJECT_SOURCE_DIR}/src/core"
)
target_link_libraries(
    tailgate_core_serve_acme
    PRIVATE
        MbedTLS::mbedtls
        nlohmann_json::nlohmann_json
        tailgate_core_crypto
)
