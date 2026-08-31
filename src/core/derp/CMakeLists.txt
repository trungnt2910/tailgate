tailgate_add_library(
    tailgate_core_derp
    STATIC
    Client.cpp
    Connection.cpp
    SendQueue.cpp
)
target_link_libraries(
    tailgate_core_derp
    PUBLIC
        tailgate_core_base
        tailgate_core_crypto
    PRIVATE
        sodium
)

add_subdirectory(impl)
