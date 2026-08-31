tailgate_add_library(
    tailgate_core_wgengine_ping
    STATIC
    Tracker.cpp
)
target_link_libraries(
    tailgate_core_wgengine_ping
    PUBLIC
        tailgate_core_crypto
        tailgate_core_disco
        tailgate_core_types_netmap
)

add_subdirectory(impl)
