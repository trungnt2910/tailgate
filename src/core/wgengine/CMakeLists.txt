add_subdirectory(magicsock)
add_subdirectory(ping)
add_subdirectory(router)
add_subdirectory(tstun)
add_subdirectory(wireguard)

tailgate_add_library(
    tailgate_core_wgengine
    STATIC
    Engine.cpp
    Session.cpp
)
target_link_libraries(
    tailgate_core_wgengine
    PUBLIC
        tailgate_core_base
        tailgate_core_control_client
        tailgate_core_derp
        tailgate_core_disco
        tailgate_core_net
        tailgate_core_types_netmap
        tailgate_core_wgengine_magicsock
        tailgate_core_wgengine_ping
        tailgate_core_wgengine_tstun
        tailgate_core_wgengine_wireguard
)

add_subdirectory(impl)
