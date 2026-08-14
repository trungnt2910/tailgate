tailgate_add_library(
    tailgate_core_net_stun
    STATIC
    Stun.cpp
)
target_link_libraries(tailgate_core_net_stun PRIVATE tailgate_core_net_packet)
