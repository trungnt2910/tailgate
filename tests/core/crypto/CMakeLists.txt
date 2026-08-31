tailgate_add_test_library(
    tailgate_tests_core_crypto
    Given_Certificate.cpp
    Given_Crypto.cpp
)
target_include_directories(
    tailgate_tests_core_crypto
    PRIVATE "${PROJECT_SOURCE_DIR}/src/core"
)
target_link_libraries(
    tailgate_tests_core_crypto
    PRIVATE
        tailgate_core
        tailgate_core_crypto_impl
        tailgate_tests_core_fakes
)
