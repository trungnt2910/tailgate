add_library(tailgate_core_wgengine_netstack_lwip INTERFACE)
target_link_libraries(
    tailgate_core_wgengine_netstack_lwip
    INTERFACE
        lwipcore
        tailgate_core_wgengine_netstack_port
)

tailgate_add_library(tailgate_core_wgengine_netstack STATIC Error.cpp Stack.cpp Stream.cpp)
target_link_libraries(tailgate_core_wgengine_netstack PUBLIC tailgate_core_base tailgate_core_net)
add_subdirectory(impl)
add_subdirectory(port)
