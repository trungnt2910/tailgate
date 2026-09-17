add_subdirectory(driveimpl)
tailgate_add_library(tailgate_core_drive STATIC FileSystemForLocal.cpp Remote.cpp)
target_link_libraries(
    tailgate_core_drive
    PUBLIC
        tailgate_core_net
        tailgate_core_types_netmap
        tailgate_core_wgengine_netstack
)
