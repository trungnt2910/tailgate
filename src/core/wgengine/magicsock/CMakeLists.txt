tailgate_add_library(
    tailgate_core_wgengine_magicsock
    STATIC
    Connection.cpp
    PeerPathState.cpp
)
target_link_libraries(
    tailgate_core_wgengine_magicsock
    PUBLIC
        tailgate_core_base
        tailgate_core_crypto
        tailgate_core_types_nettype
)

add_subdirectory(impl)
