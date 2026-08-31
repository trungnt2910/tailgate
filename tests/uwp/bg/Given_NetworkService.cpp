#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include <tailgate/di/Bindings.h>
#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/ClientSession.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/wgengine/ping/Tracker.h>
#include <tailgate/wgengine/tstun/Device.h>

#include "manager/DataPlaneManager.h"
#include "manager/SessionManager.h"
#include "service/NetworkService.h"
#include "service/PingService.h"
#include "tstun/PacketDevice.h"

#include "fakes/bg/manager/FakeDataPlaneManager.h"
#include "fakes/bg/manager/FakeSessionManager.h"

namespace tailgate::uwp::tests
{
namespace
{

namespace di = boost::di;

class Given_NetworkService : public testing::Test
{
protected:
    void SetUp() override
    {
        m_dataPlane = std::make_shared<FakeDataPlaneManager>();
        m_session = std::make_shared<FakeSessionManager>();
        m_coreInjector = std::make_unique<tailgate::di::Injector>();
        m_coreInjector->InstallSingleton<bg::PacketDevice, tailgate::wgengine::tstun::Device>();
        tailgate::di::InstallCoreBindings(*m_coreInjector);
        m_client = &m_coreInjector->create<tailgate::hosted::Client&>();
        m_hostedSession = &m_coreInjector->create<tailgate::hosted::ClientSession&>();
        m_ping = std::make_shared<bg::service::PingService>(
            *m_dataPlane, m_coreInjector->create<tailgate::wgengine::ping::Tracker&>());
        m_packetDevice = &m_coreInjector->create<bg::PacketDevice&>();
        ASSERT_EQ(&m_coreInjector->create<tailgate::wgengine::tstun::Device&>(), m_packetDevice);
        auto injector =
            di::make_injector(di::bind<bg::manager::DataPlaneManager>.to(
                                  [this](const auto&) -> bg::manager::DataPlaneManager&
                                  {
                                      return *m_dataPlane;
                                  }),
                              di::bind<bg::manager::SessionManager>.to(
                                  [this](const auto&) -> bg::manager::SessionManager&
                                  {
                                      return *m_session;
                                  }),
                              di::bind<bg::service::PingService>.to(
                                  [this](const auto&) -> bg::service::PingService&
                                  {
                                      return *m_ping;
                                  }),
                              di::bind<tailgate::hosted::Client>.to(
                                  [this](const auto&) -> tailgate::hosted::Client&
                                  {
                                      return *m_client;
                                  }),
                              di::bind<tailgate::hosted::ClientSession>.to(
                                  [this](const auto&) -> tailgate::hosted::ClientSession&
                                  {
                                      return *m_hostedSession;
                                  }),
                              di::bind<bg::PacketDevice>.to(
                                  [this](const auto&) -> bg::PacketDevice&
                                  {
                                      return *m_packetDevice;
                                  }));
        m_subject = injector.create<std::unique_ptr<bg::service::NetworkService>>();
        m_subject->Start(1);
    }

    std::unique_ptr<tailgate::di::Injector> m_coreInjector;
    std::shared_ptr<FakeDataPlaneManager> m_dataPlane;
    std::shared_ptr<FakeSessionManager> m_session;
    std::shared_ptr<bg::service::PingService> m_ping;
    tailgate::hosted::Client* m_client = nullptr;
    tailgate::hosted::ClientSession* m_hostedSession = nullptr;
    bg::PacketDevice* m_packetDevice = nullptr;
    std::unique_ptr<bg::service::NetworkService> m_subject;
};

TEST_F(Given_NetworkService, When_HeartbeatArrives_Then_HeartbeatIsReturned)
{
    const tailgate::hosted::Frame heartbeat(tailgate::hosted::MessageType::Heartbeat, {});
    tailgate::types::netmap::NetworkConfig config;
    const tailgate::crypto::Bytes32 privateKey = tailgate::crypto::GeneratePrivateKey();
    (void)m_client->Start(tailgate::hosted::ClientConfig{
        .NodePrivateKey = privateKey,
        .NodePublicKey = tailgate::crypto::X25519PublicFromPrivate(privateKey),
        .DiscoPrivateKey = tailgate::crypto::GeneratePrivateKey(),
        .Network = config,
        .ExitNode = {},
    });
    std::vector<std::vector<std::uint8_t>> localOutput;
    std::vector<std::uint8_t> remoteOutput;
    bg::service::DecapsulationContext context{
        .Message = heartbeat,
        .Client = *m_client,
        .LocalOutput = localOutput,
        .RemoteOutput = remoteOutput,
    };

    m_subject->Decapsulate(context);
    tailgate::hosted::Decoder decoder;
    decoder.Feed(remoteOutput);
    const std::optional<tailgate::hosted::Frame> response = decoder.Next();

    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(response->Type(), tailgate::hosted::MessageType::Heartbeat);
    EXPECT_TRUE(response->Payload().empty());
}

TEST_F(Given_NetworkService, When_NoRouterExists_Then_OutboundPacketIsIgnored)
{
    const std::vector<std::uint8_t> packet{1, 2, 3, 4};
    const std::string relayName = "DERP-1";
    std::vector<std::uint8_t> remoteOutput;
    bg::service::EncapsulationContext context{
        .Original = packet,
        .Client = *m_client,
        .RelayName = relayName,
        .RemoteOutput = remoteOutput,
    };

    m_subject->Encapsulate(context);

    EXPECT_TRUE(remoteOutput.empty());
    EXPECT_FALSE(context.ReconnectRequested);
}

TEST_F(Given_NetworkService, When_DerpChallengeArrives_Then_AuthenticatedResponseIsReturned)
{
    constexpr std::uint64_t RequestId = 77;
    const tailgate::crypto::Bytes32 privateKey = tailgate::crypto::GeneratePrivateKey();
    const tailgate::crypto::Bytes32 publicKey =
        tailgate::crypto::X25519PublicFromPrivate(privateKey);
    const tailgate::crypto::Bytes32 serverKey = tailgate::crypto::GeneratePrivateKey();
    const tailgate::hosted::Frame challenge(
        tailgate::hosted::MessageType::DerpChallenge,
        tailgate::hosted::ProtocolCodec::EncodeDerpChallenge(
            tailgate::hosted::DerpAuthenticationChallenge(RequestId, serverKey)));
    tailgate::types::netmap::NetworkConfig config;
    (void)m_client->Start(tailgate::hosted::ClientConfig{
        .NodePrivateKey = privateKey,
        .NodePublicKey = publicKey,
        .DiscoPrivateKey = tailgate::crypto::GeneratePrivateKey(),
        .Network = config,
        .ExitNode = {},
    });
    std::vector<std::vector<std::uint8_t>> localOutput;
    std::vector<std::uint8_t> remoteOutput;
    bg::service::DecapsulationContext context{
        .Message = challenge,
        .Client = *m_client,
        .LocalOutput = localOutput,
        .RemoteOutput = remoteOutput,
    };

    m_subject->Decapsulate(context);
    tailgate::hosted::Decoder decoder;
    decoder.Feed(remoteOutput);
    const auto frame = decoder.Next();
    ASSERT_TRUE(frame.has_value());
    const tailgate::hosted::DerpAuthenticationResponse response =
        tailgate::hosted::ProtocolCodec::DecodeDerpResponse(frame->Payload());

    EXPECT_EQ(frame->Type(), tailgate::hosted::MessageType::DerpResponse);
    EXPECT_EQ(response.RequestId(), RequestId);
    EXPECT_FALSE(response.ClientInfo().empty());
}

} // namespace
} // namespace tailgate::uwp::tests
