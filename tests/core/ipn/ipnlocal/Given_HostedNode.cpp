#include <memory>
#include <system_error>

#include <gtest/gtest.h>

#include <tailgate/ipn/ipnlocal/HostedNode.h>
#include <tailgate/ipn/ipnlocal/NodeError.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/packet/Ipv4.h>

#include "fakes/di/FakeNetworkBindings.h"
#include "fakes/ipn/ipnlocal/FakeLocalServices.h"

namespace tailgate
{
namespace
{

constexpr base::EventToken DeviceToken{.Value = 1};

class Given_HostedNode : public testing::Test
{
protected:
    Given_HostedNode()
    {
        tests::fakes::InstallFakeNetworkBindings(Injector);
        Network.SelfAddress("100.64.0.1");
        Network.SelfName("self.example.ts.net");
        Network.MagicDnsDomain("example.ts.net");
        Network.Domain("example.ts.net");
        Network.DnsResolver("100.100.100.100");
        Network.DnsRoutes({{"example.ts.net", {}}});
        hosted::ClientConfig config;
        config.NodePrivateKey.front() = 7;
        config.NodePublicKey = crypto::X25519PublicFromPrivate(config.NodePrivateKey);
        config.DiscoPrivateKey.front() = 11;
        Network.SelfKey("nodekey:" + crypto::BytesToHex(config.NodePublicKey.data(),
                                                        config.NodePublicKey.size()));
        config.Network = Network;
        (void)Injector.create<hosted::Client&>().Start(config);
        Subject = std::make_unique<ipn::ipnlocal::HostedNode>(
            Injector.create<hosted::Client&>(),
            Injector.create<wgengine::Session&>(),
            Injector.create<wgengine::Engine&>(),
            Services,
            Injector.create<ipn::ipnlocal::DnsForwarder&>(),
            Injector.create<wgengine::ping::Tracker&>(),
            Injector.create<base::TimeProvider&>(),
            Injector.create<hosted::Dns&>(),
            Injector.create<hosted::Recovery&>());
        hosted::ConnectionOptions reconnect;
        reconnect.Client = config;
        reconnect.Socket.ConnectAddress = "192.0.2.1";
        reconnect.Socket.Service = "443";
        Subject->Start({.Stream = std::make_unique<tests::fakes::FakeTcpSocket>(Socket),
                        .RelayPublicKey = {},
                        .RelaySession = {"example.ts.net", "relay", "192.0.2.1", {}},
                        .FrameDecoder = {},
                        .Configuration = config,
                        .Reconnect = reconnect},
                       {.Name = "test", .ReadinessToken = DeviceToken},
                       {},
                       "relay.example.com");
        Events().Next.Status = base::EventWaitStatus::Woken;
    }

    tests::fakes::FakeEventLoop& Events()
    {
        return dynamic_cast<tests::fakes::FakeEventLoop&>(Injector.create<base::EventLoop&>());
    }

    tests::fakes::FakeDevice& Device()
    {
        return Injector.create<tests::fakes::FakeDevice&>();
    }

    ipn::ipnlocal::NodeEvents Wait()
    {
        return Subject->Wait(16, 16, 4096);
    }

    di::Injector Injector;
    types::netmap::NetworkConfig Network;
    tests::fakes::FakeLocalServices Services;
    std::shared_ptr<tests::fakes::FakeTcpSocketState> Socket =
        std::make_shared<tests::fakes::FakeTcpSocketState>();
    std::unique_ptr<ipn::ipnlocal::HostedNode> Subject;
};

TEST_F(Given_HostedNode, When_RelayConfirmsDataPath_Then_BackendBecomesReady)
{
    Socket->Incoming.push_back(hosted::Frame(hosted::MessageType::DataPathReady, {}).Encode());
    const bool initiallyReady = Subject->Ready();

    const auto completed = Wait();

    EXPECT_FALSE(initiallyReady);
    EXPECT_TRUE(completed.DataPathReady);
    EXPECT_TRUE(Subject->Ready());
}

TEST_F(Given_HostedNode, When_LocalServicesProduceOutput_Then_PacketReachesHostWithoutRelayInput)
{
    Services.Output.push_back({.Peer = {}, .Bytes = {1, 2, 3}, .ForwardFromHost = false});

    (void)Wait();

    EXPECT_EQ(Device().Written, (std::vector<std::vector<std::uint8_t>>{{1, 2, 3}}));
    EXPECT_EQ(Services.Stops, 0);
}

TEST_F(Given_HostedNode, When_PacketDeviceBackpressures_Then_LocalOutputSurvivesUntilWritable)
{
    Device().WriteResult = wgengine::tstun::DeviceIoResult::WouldBlock;
    Services.Output.push_back({.Peer = {}, .Bytes = {1, 2, 3}, .ForwardFromHost = false});

    (void)Wait();
    const bool writeInterest = Device().WriteInterest;
    Device().WriteResult = wgengine::tstun::DeviceIoResult::Complete;
    Events().Next.Events.push_back(
        {.Token = DeviceToken, .Readiness = base::EventReadiness::Writable});
    (void)Wait();

    EXPECT_TRUE(writeInterest);
    EXPECT_EQ(Device().Written, (std::vector<std::vector<std::uint8_t>>{{1, 2, 3}}));
}

TEST_F(Given_HostedNode, When_TransportRetires_Then_SharedLocalServicesRemainAlive)
{
    const auto updates = Services.Updates;

    Subject.reset();

    EXPECT_TRUE(Socket->Closed);
    EXPECT_EQ(Services.Stops, 0);
    EXPECT_EQ(Services.Updates, updates);
    EXPECT_FALSE(Device().Closed);
}

TEST_F(Given_HostedNode, When_IdentityChanges_Then_UpdateIsRejected)
{
    auto next = Network;
    next.SelfKey("nodekey:" + std::string(64, '2'));

    const auto update = [&]()
    {
        Subject->UpdateNetwork(next);
    };

    EXPECT_THROW(update(), ipn::ipnlocal::NodeError);
    EXPECT_EQ(Subject->Network().SelfKey(), Network.SelfKey());
}

TEST_F(Given_HostedNode, When_ControlUpdatesPeers_Then_LocalServicesReceiveTheNewMap)
{
    auto next = Network;
    next.SelfName("renamed.example.ts.net");
    const auto before = Services.Updates;

    Subject->UpdateNetwork(next);

    EXPECT_EQ(Subject->Network().SelfName(), "renamed.example.ts.net");
    EXPECT_GT(Services.Updates, before);
    EXPECT_EQ(Services.Stops, 0);
}

TEST_F(Given_HostedNode, When_RelayCloses_Then_TransportFailureIsReportedWithoutStoppingServices)
{
    Socket->Closed = true;

    const auto completed = Wait();

    EXPECT_TRUE(completed.TransportFailure.has_value());
    EXPECT_FALSE(Subject->Ready());
    EXPECT_EQ(Services.Stops, 0);
}

TEST_F(Given_HostedNode, When_MagicDnsReplyArrives_Then_OriginalClientAndQueryIdAreRestored)
{
    const auto client = net::Endpoint::Parse("127.0.0.1:12000");
    const auto query = net::dns::DnsQuery::Build("self.example.ts.net", 42);
    const auto forwarded = Subject->ForwardDns(client, query, {"192.0.2.53"});
    ASSERT_TRUE(forwarded.TunnelPacket.has_value());
    const auto response = net::packet::Ipv4UdpDatagram::Build(
        net::Ipv4Address::Parse("100.100.100.100").HostOrder(),
        net::Ipv4Address::Parse(Network.SelfAddress()).HostOrder(),
        53,
        client.Port(),
        forwarded.Payload);
    Socket->Incoming.push_back(
        hosted::Frame(hosted::MessageType::TailnetDnsResponse, response).Encode());

    const auto completed = Wait();

    EXPECT_EQ(completed.Received.size(), 1U);
    EXPECT_EQ(completed.Received.at(0).Dns.value().Client, client);
    EXPECT_EQ(completed.Received.at(0).Dns.value().Payload, query);
    EXPECT_TRUE(Device().Written.empty());
}

TEST_F(Given_HostedNode, When_NoPeerMatchesPing_Then_NoRequestIsStarted)
{
    wgengine::ping::Request request{.Id = 1,
                                    .Target = "missing.example.ts.net",
                                    .PingMode = wgengine::ping::Mode::Disco,
                                    .Timeout = std::chrono::seconds(1),
                                    .Relay = {}};

    const auto result = Subject->StartPing(request);

    EXPECT_NE(result, wgengine::ping::StartStatus::Ready);
}

} // namespace

} // namespace tailgate
