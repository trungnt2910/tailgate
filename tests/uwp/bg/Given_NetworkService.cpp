#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include <tailgate/hosted/Protocol.h>

#include "manager/DataPlaneManager.h"
#include "manager/SessionManager.h"
#include "service/NetworkService.h"
#include "service/PingService.h"

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
        m_ping = std::make_shared<bg::service::PingService>(*m_dataPlane);
        auto injector = di::make_injector(di::bind<bg::manager::DataPlaneManager>.to(
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
                                              }));
        m_subject = injector.create<std::unique_ptr<bg::service::NetworkService>>();
    }

    std::shared_ptr<FakeDataPlaneManager> m_dataPlane;
    std::shared_ptr<FakeSessionManager> m_session;
    std::shared_ptr<bg::service::PingService> m_ping;
    std::unique_ptr<bg::service::NetworkService> m_subject;
};

TEST_F(Given_NetworkService, When_HeartbeatArrives_Then_HeartbeatIsReturned)
{
    const tailgate::hosted::Frame heartbeat{.Type = tailgate::hosted::MessageType::Heartbeat,
                                            .Payload = {}};
    tailgate::types::netmap::NetworkConfig config;
    const tailgate::crypto::Bytes32 privateKey{};
    const tailgate::crypto::Bytes32 publicKey{};
    const std::string exitNode;
    std::vector<std::vector<std::uint8_t>> localOutput;
    std::vector<std::uint8_t> remoteOutput;
    bg::service::DecapsulationContext context{
        .Message = heartbeat,
        .Config = config,
        .NodePrivateKey = privateKey,
        .NodePublicKey = publicKey,
        .ExitNode = exitNode,
        .LocalOutput = localOutput,
        .RemoteOutput = remoteOutput,
    };

    m_subject->Decapsulate(context);
    tailgate::hosted::Decoder decoder;
    decoder.Feed(remoteOutput);
    const std::optional<tailgate::hosted::Frame> response = decoder.Next();

    EXPECT_TRUE(response.has_value());
    EXPECT_EQ(response.value_or(tailgate::hosted::Frame{}).Type,
              tailgate::hosted::MessageType::Heartbeat);
    EXPECT_TRUE(response.value_or(tailgate::hosted::Frame{}).Payload.empty());
}

TEST_F(Given_NetworkService, When_NoRouterExists_Then_OutboundPacketIsIgnored)
{
    const std::vector<std::uint8_t> packet{1, 2, 3, 4};
    const tailgate::types::netmap::NetworkConfig config;
    const std::string exitNode;
    const std::string relayName = "DERP-1";
    std::vector<std::uint8_t> remoteOutput;
    bg::service::EncapsulationContext context{
        .Original = packet,
        .Config = config,
        .Disco = nullptr,
        .Router = nullptr,
        .ExitNode = exitNode,
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
    const tailgate::hosted::Frame challenge{
        .Type = tailgate::hosted::MessageType::DerpChallenge,
        .Payload =
            tailgate::hosted::EncodeDerpChallenge(tailgate::hosted::DerpAuthenticationChallenge{
                .RequestId = RequestId,
                .ServerKey = serverKey,
            }),
    };
    tailgate::types::netmap::NetworkConfig config;
    const std::string exitNode;
    std::vector<std::vector<std::uint8_t>> localOutput;
    std::vector<std::uint8_t> remoteOutput;
    bg::service::DecapsulationContext context{
        .Message = challenge,
        .Config = config,
        .NodePrivateKey = privateKey,
        .NodePublicKey = publicKey,
        .ExitNode = exitNode,
        .LocalOutput = localOutput,
        .RemoteOutput = remoteOutput,
    };

    m_subject->Decapsulate(context);
    tailgate::hosted::Decoder decoder;
    decoder.Feed(remoteOutput);
    const auto frame = decoder.Next();
    ASSERT_TRUE(frame.has_value());
    const tailgate::hosted::DerpAuthenticationResponse response =
        tailgate::hosted::DecodeDerpResponse(frame->Payload);

    EXPECT_EQ(frame->Type, tailgate::hosted::MessageType::DerpResponse);
    EXPECT_EQ(response.RequestId, RequestId);
    EXPECT_FALSE(response.ClientInfo.empty());
}

} // namespace
} // namespace tailgate::uwp::tests
