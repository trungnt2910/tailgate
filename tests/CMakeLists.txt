tailgate_add_test_executable(
    tailgate_tests
    Given_Arguments.cpp
    Given_ByteStream.cpp
    Given_CApi.cpp
    Given_ControlRequests.cpp
    Given_Crypto.cpp
    Given_Disco.cpp
    Given_Dns.cpp
    Given_NetworkMap.cpp
    Given_ReplayWindow.cpp
    Given_WireGuardTunnel.cpp
)
target_link_libraries(tailgate_tests PRIVATE tailgate_c tailgate_cli)
