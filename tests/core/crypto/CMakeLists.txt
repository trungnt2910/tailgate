tailgate_add_test_library(
    tailgate_tests_core_crypto
    Given_Crypto.cpp
)
target_link_libraries(tailgate_tests_core_crypto PRIVATE tailgate_core)
