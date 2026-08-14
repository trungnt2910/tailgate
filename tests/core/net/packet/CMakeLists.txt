tailgate_add_test_library(
    tailgate_tests_core_net_packet
    Given_Ipv4.cpp
    Given_Tsmp.cpp
)
target_link_libraries(tailgate_tests_core_net_packet PRIVATE tailgate_core)
