tailgate_add_library(
    tailgate_core_net
    STATIC
    Endpoint.cpp
    Ipv4Address.cpp
)

add_subdirectory(dns)
add_subdirectory(http)
add_subdirectory(packet)
add_subdirectory(stun)
add_subdirectory(tls)
