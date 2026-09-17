tailgate_add_library(
    tailgate_core_net_http
    STATIC
    Client.cpp
    Message.cpp
    MessageEncoder.cpp
    MessageParser.cpp
)

add_subdirectory(impl)
