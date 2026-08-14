tailgate_add_test_library(
    tailgate_tests_core_net_stun
    Given_Stun.cpp
)
target_link_libraries(tailgate_tests_core_net_stun PRIVATE tailgate_core)
