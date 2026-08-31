tailgate_add_library(
    tailgate_core_types_nettype
    STATIC
    TcpSocket.cpp
    UdpSocket.cpp
)
target_link_libraries(tailgate_core_types_nettype PUBLIC tailgate_core_net)
