tailgate_add_library(
    tailgate_linux
    STATIC
    ControlStream.cpp
    LinuxDataplaneEvents.cpp
    LinuxAcme.cpp
    LinuxCaBundle.cpp
    LinuxDerpWorker.cpp
    FdStream.cpp
    LinuxFiles.cpp
    LinuxFrontend.cpp
    LinuxHost.cpp
    LinuxNetwork.cpp
    LinuxPeerApiServer.cpp
    LinuxPingIpc.cpp
    LinuxQrCode.cpp
    LinuxRelayServer.cpp
    LinuxState.cpp
    LinuxStatusWriter.cpp
    TcpStream.cpp
)
target_link_libraries(tailgate_linux PUBLIC tailgate_core)
target_link_libraries(tailgate_linux PRIVATE nlohmann_json::nlohmann_json)

tailgate_add_executable(tailgate Main.cpp)
target_link_libraries(tailgate PRIVATE tailgate_cli tailgate_linux)
