tailgate_add_test_library(
    tailgate_tests_core_net_dns
    Given_Dns.cpp
    Given_ResolverConfig.cpp
    Given_TailnetDns.cpp
)
target_link_libraries(tailgate_tests_core_net_dns PRIVATE tailgate_core)
