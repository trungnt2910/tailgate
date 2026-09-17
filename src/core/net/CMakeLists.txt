tailgate_add_library(
    tailgate_core_net
    STATIC
    Endpoint.cpp
    IpAddress.cpp
    IpRange.cpp
    Ipv4Address.cpp
)
target_link_libraries(tailgate_core_net PRIVATE tailgate_core_wgengine_netstack_lwip)

add_subdirectory(dns)
add_subdirectory(http)
add_subdirectory(packet)
add_subdirectory(stun)
add_subdirectory(tls)
