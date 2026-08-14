tailgate_add_test_library(
    tailgate_tests_core_hosted
    Given_RelayProtocol.cpp
)
target_link_libraries(tailgate_tests_core_hosted PRIVATE tailgate_core)
