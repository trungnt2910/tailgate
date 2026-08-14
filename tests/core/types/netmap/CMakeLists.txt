tailgate_add_test_library(
    tailgate_tests_core_types_netmap
    Given_NetworkMapQueries.cpp
)
target_link_libraries(tailgate_tests_core_types_netmap PRIVATE tailgate_core)
