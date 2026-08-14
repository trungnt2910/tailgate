tailgate_add_test_library(
    tailgate_tests_core_serve_acme
    Given_AcmeClient.cpp
    Given_AcmeCrypto.cpp
)
target_link_libraries(tailgate_tests_core_serve_acme PRIVATE tailgate_core)
