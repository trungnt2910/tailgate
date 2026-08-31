tailgate_add_test_library(
    tailgate_tests_core_net
    Given_Endpoint.cpp
    Given_Ipv4Address.cpp
)
target_link_libraries(tailgate_tests_core_net PRIVATE tailgate_core)

add_subdirectory(dns)
add_subdirectory(http)
add_subdirectory(packet)
add_subdirectory(stun)
add_subdirectory(tls)
