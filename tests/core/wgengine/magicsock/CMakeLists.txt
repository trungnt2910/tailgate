tailgate_add_test_library(
    tailgate_tests_core_wgengine_magicsock
    Given_HostedDiscoProbes.cpp
)
target_link_libraries(tailgate_tests_core_wgengine_magicsock PRIVATE tailgate_core)
