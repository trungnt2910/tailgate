tailgate_add_test_library(
    tailgate_tests_core_control_client
    Given_ControlDialer.cpp
    Given_ControlRequests.cpp
    Given_NetworkMapParser.cpp
    Given_RetryBackoff.cpp
)
target_link_libraries(tailgate_tests_core_control_client PRIVATE tailgate_core)
