tailgate_add_library(tailgate_core_wgengine_netstack_port STATIC Services.c)
target_include_directories(
    tailgate_core_wgengine_netstack_port
    SYSTEM PUBLIC
        "${Lwip_SOURCE_DIR}/src/include"
)
target_include_directories(
    tailgate_core_wgengine_netstack_port
    PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}"
)
