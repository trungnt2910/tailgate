tailgate_add_library(
    tailgate_core_net_packet
    STATIC
    Ipv4.cpp
    Tsmp.cpp
)
target_link_libraries(tailgate_core_net_packet PUBLIC tailgate_core_net)
