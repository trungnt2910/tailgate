tailgate_add_library(tailgate_core_ipn_ipnlocal STATIC LocalServices.cpp)
target_link_libraries(
    tailgate_core_ipn_ipnlocal
    PUBLIC
        tailgate_core_base
        tailgate_core_crypto
        tailgate_core_types_netmap
)
add_subdirectory(impl)
