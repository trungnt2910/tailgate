#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/packet/Ipv4.h>

#include "common/UwpAppServiceProtocol.h"
#include "common/VpnConstants.h"

#include "service/PingService.h"

#include "fakes/bg/manager/FakeDataPlaneManager.h"
#include "fakes/di/FakeNetworkBindings.h"
#include "fakes/ipn/ipnlocal/FakeNodeBackend.h"

namespace tailgate::uwp::tests
{
namespace
{

constexpr std::uint32_t AppAddress =
    tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 1).HostOrder();
constexpr std::uint16_t AppPort = 49152;
constexpr std::uint64_t RequestSequence = 42;

std::optional<app_service::PingResponse>
DecodeResponse(const std::vector<std::vector<std::uint8_t>>& packets)
{
    if (packets.size() != 1)
    {
        return std::nullopt;
    }
    const auto datagram = tailgate::net::packet::Ipv4UdpDatagram::Parse(packets.front());
    if (!datagram)
    {
        return std::nullopt;
    }
    const auto message = app_service::DecodeMessage(datagram->Payload());
    return message ? app_service::DecodePingResponse(*message) : std::nullopt;
}

class Given_PingService : public testing::Test
{
protected:
    void SetUp() override
    {
        tailgate::tests::fakes::InstallFakeNetworkBindings(Injector);
        Injector.InstallSingleton<FakeDataPlaneManager, bg::manager::DataPlaneManager>();
        Subject = Injector.create<std::unique_ptr<bg::service::PingService>>();
        Network.SelfAddress("192.0.2.1");
    }

    tailgate::types::netmap::PeerConfig Peer()
    {
        tailgate::types::netmap::PeerConfig peer;
        peer.Name("peer.example.ts.net");
        peer.Address("192.0.2.2");
        peer.Key("nodekey:" +
                 tailgate::crypto::BytesToHex(RemoteNodeKey.data(), RemoteNodeKey.size()));
        peer.DiscoKey("discokey:" + tailgate::crypto::BytesToHex(RemoteDisco.PublicKey().data(),
                                                                 RemoteDisco.PublicKey().size()));
        return peer;
    }

    std::vector<std::uint8_t> Packet(std::uint32_t source = AppAddress)
    {
        return tailgate::net::packet::Ipv4UdpDatagram::Build(
            source,
            VpnConstants::Network::ServiceIpv4Address,
            AppPort,
            VpnConstants::AppService::Port,
            app_service::EncodePingRequest(
                {.Sequence = RequestSequence, .Target = "peer.example.ts.net"}));
    }

    void StartHosted()
    {
        Node.Config = Network;
        const auto packet = Packet();
        const std::string relay = "Relay-Node";
        const std::string exit;
        bg::service::EncapsulationContext context{
            .Original = packet, .Node = Node, .RelayName = relay, .ExitNode = exit};
        Subject->Encapsulate(context);
    }

    tailgate::tests::fakes::FakeNodeBackend Node;

    tailgate::tests::fakes::FakeTimeProvider& Clock()
    {
        return dynamic_cast<tailgate::tests::fakes::FakeTimeProvider&>(
            Injector.create<tailgate::base::TimeProvider&>());
    }

    tailgate::di::Injector Injector;
    tailgate::types::netmap::NetworkConfig Network;
    std::unique_ptr<bg::service::PingService> Subject;
    const tailgate::crypto::Bytes32 RemoteNodeKey = tailgate::crypto::GeneratePrivateKey();
    tailgate::disco::Disco RemoteDisco{tailgate::crypto::GeneratePrivateKey(), RemoteNodeKey};
};

TEST_F(Given_PingService, When_PeerDoesNotExist_Then_TypedErrorIsReturned)
{
    std::vector<std::vector<std::uint8_t>> responses;
    Node.PingStatus = tailgate::wgengine::ping::StartStatus::NoMatchingPeer;

    StartHosted();
    Subject->FlushLocal(responses);
    const auto response = DecodeResponse(responses);
    ASSERT_TRUE(response);

    EXPECT_EQ(Node.Requests.size(), 1U);
    EXPECT_EQ(response->Result, app_service::Status::NoMatchingPeer);
    EXPECT_EQ(response->Sequence, RequestSequence);
}

TEST_F(Given_PingService, When_PeerHasNoUsableDiscoState_Then_TypedErrorIsReturned)
{
    auto peer = Peer();
    peer.DiscoKey({});
    Network.Peers({peer});
    std::vector<std::vector<std::uint8_t>> responses;
    Node.PingStatus = tailgate::wgengine::ping::StartStatus::NoDiscoKey;

    StartHosted();
    Subject->FlushLocal(responses);
    const auto response = DecodeResponse(responses);
    ASSERT_TRUE(response);

    EXPECT_EQ(Node.Requests.size(), 1U);
    EXPECT_EQ(response->Result, app_service::Status::NoDiscoKey);
}

TEST_F(Given_PingService, When_HostedPingCompletes_Then_ReportsCoreLatencyAndRelay)
{
    StartHosted();
    ASSERT_EQ(Node.Requests.size(), 1U);
    std::vector<std::vector<std::uint8_t>> responses;

    Subject->Complete({.RequestId = Node.Requests.front().Id,
                       .Responded = true,
                       .Latency = std::chrono::milliseconds(12),
                       .PeerName = "peer.example.ts.net",
                       .PeerAddress = "192.0.2.2",
                       .Relay = Node.Requests.front().Relay},
                      false,
                      {});
    Subject->FlushLocal(responses);
    const auto response = DecodeResponse(responses);
    ASSERT_TRUE(response);

    EXPECT_EQ(response->Result, app_service::Status::Ok);
    EXPECT_EQ(response->Sequence, RequestSequence);
    EXPECT_EQ(response->LatencyMicroseconds, 12000U);
    EXPECT_EQ(response->Relay, "relay-node");
    EXPECT_FALSE(response->Direct);
}

TEST_F(Given_PingService, When_HostedPingExpires_Then_ExplicitTimeoutIsReturned)
{
    Network.Peers({Peer()});
    StartHosted();
    ASSERT_EQ(Node.Requests.size(), 1U);
    std::vector<std::vector<std::uint8_t>> responses;

    Clock().Advance(std::chrono::seconds(11));
    Subject->Complete({.RequestId = Node.Requests.front().Id,
                       .Responded = false,
                       .Latency = {},
                       .PeerName = "peer.example.ts.net",
                       .PeerAddress = "192.0.2.2",
                       .Relay = "relay-node"},
                      false,
                      {});
    Subject->FlushLocal(responses);
    const auto response = DecodeResponse(responses);
    ASSERT_TRUE(response);

    EXPECT_EQ(response->Result, app_service::Status::Timeout);
    EXPECT_EQ(response->Sequence, RequestSequence);
    EXPECT_FALSE(Subject->NextDeadline());
}

TEST_F(Given_PingService, When_RetryIntervalPasses_Then_HostedDeadlineRemainsExpiration)
{
    Network.Peers({Peer()});
    const auto started = Clock().Now();
    StartHosted();
    ASSERT_EQ(Node.Requests.size(), 1U);
    std::vector<std::vector<std::uint8_t>> responses;

    Clock().Advance(std::chrono::seconds(2));
    Subject->FlushLocal(responses);
    const auto deadline = Subject->NextDeadline();

    EXPECT_TRUE(responses.empty());
    EXPECT_EQ(deadline, started + std::chrono::seconds(10));
}

TEST_F(Given_PingService, When_NativePingCompletes_Then_ReportsDirectEndpoint)
{
    Node.Config = Network;
    const auto packet = Packet();
    const std::string relay;
    const std::string exit;
    bg::service::EncapsulationContext context{
        .Original = packet, .Node = Node, .RelayName = relay, .ExitNode = exit};
    Subject->Encapsulate(context);
    ASSERT_TRUE(context.Handled);
    ASSERT_EQ(Node.Requests.size(), 1U);
    const auto started = Node.Requests.front();
    std::vector<std::vector<std::uint8_t>> responses;

    Subject->Complete({.RequestId = started.Id,
                       .Responded = true,
                       .Latency = std::chrono::milliseconds(4),
                       .PeerName = "peer.example.ts.net",
                       .PeerAddress = "192.0.2.2",
                       .Relay = "derp-1"},
                      true,
                      "192.0.2.2:1234");
    Subject->FlushLocal(responses);
    const auto response = DecodeResponse(responses);
    ASSERT_TRUE(response);

    EXPECT_EQ(started.Target, "peer.example.ts.net");
    EXPECT_EQ(response->Sequence, RequestSequence);
    EXPECT_EQ(response->LatencyMicroseconds, 4000U);
    EXPECT_TRUE(response->Direct);
    EXPECT_TRUE(response->Relay.empty());
    EXPECT_EQ(response->Endpoint, "192.0.2.2:1234");
}

TEST_F(Given_PingService, When_NativePingUsesDerp_Then_RegionLabelIsUppercase)
{
    Node.Config = Network;
    const auto packet = Packet();
    const std::string relay;
    const std::string exit;
    bg::service::EncapsulationContext context{
        .Original = packet, .Node = Node, .RelayName = relay, .ExitNode = exit};
    Subject->Encapsulate(context);
    ASSERT_TRUE(context.Handled);
    ASSERT_EQ(Node.Requests.size(), 1U);
    const auto started = Node.Requests.front();
    std::vector<std::vector<std::uint8_t>> responses;

    Subject->Complete({.RequestId = started.Id,
                       .Responded = true,
                       .Latency = std::chrono::milliseconds(4),
                       .PeerName = "peer.example.ts.net",
                       .PeerAddress = "192.0.2.2",
                       .Relay = "syd"},
                      false,
                      "");
    Subject->FlushLocal(responses);
    const auto response = DecodeResponse(responses);
    ASSERT_TRUE(response);

    EXPECT_EQ(started.Target, "peer.example.ts.net");
    EXPECT_EQ(response->Sequence, RequestSequence);
    EXPECT_EQ(response->LatencyMicroseconds, 4000U);
    EXPECT_FALSE(response->Direct);
    EXPECT_EQ(response->Relay, "SYD");
    EXPECT_TRUE(response->Endpoint.empty());
}

TEST_F(Given_PingService, When_RequestSourceIsNotTheHost_Then_DoesNotSendProbe)
{
    Node.Config = Network;
    const auto packet = Packet(tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 3).HostOrder());
    const std::string relay;
    const std::string exit;
    bg::service::EncapsulationContext context{
        .Original = packet, .Node = Node, .RelayName = relay, .ExitNode = exit};

    Subject->Encapsulate(context);

    EXPECT_TRUE(context.Handled);
    EXPECT_TRUE(Node.Requests.empty());
    EXPECT_FALSE(Subject->HasLocalOutput());
}

} // namespace
} // namespace tailgate::uwp::tests
