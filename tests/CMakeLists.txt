tailgate_add_library(
    tailgate_tests
    STATIC
    Given_AcmeClient.cpp
    Given_AcmeCrypto.cpp
    Given_Arguments.cpp
    Given_ByteStream.cpp
    Given_CApi.cpp
    Given_ControlDialer.cpp
    Given_ControlRequests.cpp
    Given_Crypto.cpp
    Given_DerpClient.cpp
    Given_DerpSendQueue.cpp
    Given_Disco.cpp
    Given_Dns.cpp
    Given_HandshakeLimiter.cpp
    Given_H2.cpp
    Given_Ipv4.cpp
    Given_Logging.cpp
    Given_NetworkMap.cpp
    Given_NoiseTransport.cpp
    Given_PeerApiIngress.cpp
    Given_QrCode.cpp
    Given_ReplayWindow.cpp
    Given_RetryBackoff.cpp
    Given_ResolverConfig.cpp
    Given_RelayProtocol.cpp
    Given_Stun.cpp
    Given_Strings.cpp
    Given_TailnetDns.cpp
    Given_TlsWriteProgress.cpp
    Given_Tsmp.cpp
    Given_WireGuardTunnel.cpp
    Given_WireGuardRouter.cpp
)
target_link_libraries(tailgate_tests PUBLIC GTest::gtest PRIVATE tailgate_c tailgate_cli)
target_include_directories(tailgate_tests PRIVATE "${PROJECT_SOURCE_DIR}/src/core")

if(TAILGATE_BUILD_LINUX)
    add_subdirectory(linux)
endif()

if(TAILGATE_BUILD_UWP)
    add_subdirectory(uwp)
endif()
