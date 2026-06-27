tailgate_add_library(
    tailgate_linux
    STATIC
    LinuxDataplaneEvents.cpp
    LinuxDerpWorker.cpp
    LinuxFiles.cpp
    LinuxFrontend.cpp
    LinuxHost.cpp
    LinuxNetwork.cpp
    LinuxPingIpc.cpp
    LinuxState.cpp
    LinuxStatusWriter.cpp
    TcpStream.cpp
)
target_link_libraries(tailgate_linux PUBLIC tailgate_core)
target_link_libraries(tailgate_linux PRIVATE nlohmann_json::nlohmann_json)
target_compile_definitions(tailgate_linux PRIVATE TAILGATE_VERSION="${PROJECT_VERSION}")
