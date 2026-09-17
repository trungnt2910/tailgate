tailgate_add_library(
    tailgate_core_ipn_ipnlocal_impl
    STATIC
    LocalServicesImpl.cpp
)
target_include_directories(tailgate_core_ipn_ipnlocal_impl PRIVATE ${PROJECT_SOURCE_DIR}/src/core)
target_link_libraries(
    tailgate_core_ipn_ipnlocal_impl
    PUBLIC
        tailgate_core_ipn_ipnlocal
    PRIVATE
        tailgate_core_drive
        tailgate_core_net_packet
        tailgate_core_wgengine_netstack
)
