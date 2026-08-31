add_subdirectory(event)
add_subdirectory(impl)

tailgate_add_library(
    tailgate_linux
    STATIC
    DataplaneEvents.cpp
    DI.cpp
    DirectConnection.cpp
    FdStream.cpp
    FileChangeWaiter.cpp
    Files.cpp
    Frontend.cpp
    HostedClient.cpp
    HostedConnectionRegistry.cpp
    HostedServer.cpp
    Lifecycle.cpp
    Network.cpp
    PacketDescriptorProvider.cpp
    PeerApiServer.cpp
    PingIpc.cpp
    ProcessWait.cpp
    QrCode.cpp
    Registration.cpp
    RelayServer.cpp
    State.cpp
    StatusWriter.cpp
    TunnelRunner.cpp
)
target_link_libraries(
    tailgate_linux
    PUBLIC
        tailgate_core
    PRIVATE
        Boost::algorithm
        nlohmann_json::nlohmann_json
        tailgate_linux_impl
)

tailgate_add_executable(tailgate Main.cpp)
target_link_libraries(tailgate PRIVATE tailgate_cli tailgate_linux)
