#include <algorithm>
#include <chrono>
#include <memory>
#include <utility>

#include <gtest/gtest.h>

#include <tailgate/ipn/ipnlocal/NativeNode.h>
#include <tailgate/ipn/ipnlocal/NodeError.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/wgengine/PeerProtocol.h>
#include <tailgate/wgengine/magicsock/Connection.h>
#include <tailgate/wgengine/wireguard/Tunnel.h>

#include "fakes/derp/FakeConnection.h"
#include "fakes/di/FakeNetworkBindings.h"
#include "fakes/ipn/ipnlocal/FakeLocalServices.h"

namespace tailgate
{
namespace
{

constexpr base::EventToken DeviceToken{.Value = 1};
constexpr base::EventToken DerpToken{.Value = 2};
constexpr base::EventToken UdpToken{.Value = 3};
constexpr std::size_t MaximumPackets = 16;
constexpr std::size_t MaximumPacketSize = 4096;

class Given_NativeNode : public testing::Test, public ipn::ipnlocal::DerpTransportFactory
{
protected:
    void SetNetworkInterface(const std::string&) override
    {
    }

    Given_NativeNode()
    {
        tests::fakes::InstallFakeNetworkBindings(Injector);
        Network.SelfAddress("100.64.0.1");
        Network.SelfName("self.example.ts.net");
        Network.MagicDnsDomain("example.ts.net");
        Options.NodePrivateKey.front() = 7;
        Options.DiscoPrivateKey.front() = 11;
        Options.NodePublicKey = crypto::X25519PublicFromPrivate(Options.NodePrivateKey);
        Network.SelfKey("nodekey:" + crypto::BytesToHex(Options.NodePublicKey.data(),
                                                        Options.NodePublicKey.size()));
        Network.DerpRegion(1);
        Network.DerpHost("derp.example.com");
        Subject = std::make_unique<ipn::ipnlocal::NativeNode>(
            Injector.create<wgengine::Session&>(),
            Injector.create<wgengine::Engine&>(),
            Injector.create<wgengine::magicsock::Connection&>(),
            Services,
            Injector.create<ipn::ipnlocal::DnsForwarder&>(),
            Injector.create<wgengine::ping::Tracker&>(),
            Injector.create<base::TimeProvider&>(),
            *this);
        Events().Next.Status = base::EventWaitStatus::Woken;
    }

    std::unique_ptr<derp::Connection>
    Create(int region, const std::string&, bool, std::size_t, bool enabled) override
    {
        Regions.push_back(region);
        auto connection = std::make_unique<tests::fakes::derp::FakeConnection>(
            DerpToken, derp::DerpClient::Packet{});
        connection->SetEnabled(enabled);
        Derps.push_back(connection.get());
        return connection;
    }

    static types::netmap::PeerConfig Peer()
    {
        types::netmap::PeerConfig peer;
        peer.Key("nodekey:" + std::string(64, '1'));
        peer.Name("peer.example.ts.net");
        peer.Address("100.64.0.2");
        peer.AllowedPrefixes({*net::packet::Ipv4Prefix::Parse("100.64.0.2/32")});
        peer.DerpRegion(1);
        peer.DerpHost("derp.example.com");
        return peer;
    }

    void Start(std::optional<net::Endpoint> stunServer = std::nullopt)
    {
        const types::nettype::UdpSocketOptions udp{
            .BindEndpoint = {}, .NetworkInterface = "test-adapter", .ReadinessToken = UdpToken};
        ASSERT_TRUE(Injector.create<wgengine::magicsock::Connection&>().Open(udp));
        Subject->Start(
            Network, Options, {.Name = "test", .ReadinessToken = DeviceToken}, udp, stunServer);
    }

    ipn::ipnlocal::NodeEvents Wait()
    {
        return Subject->Wait(MaximumPackets, MaximumPackets, MaximumPacketSize);
    }

    tests::fakes::FakeDevice& Device()
    {
        return Injector.create<tests::fakes::FakeDevice&>();
    }

    tests::fakes::FakeEventLoop& Events()
    {
        return dynamic_cast<tests::fakes::FakeEventLoop&>(Injector.create<base::EventLoop&>());
    }

    di::Injector Injector;
    tests::fakes::FakeLocalServices Services;
    types::netmap::NetworkConfig Network;
    wgengine::SessionOptions Options;
    std::vector<int> Regions;
    std::vector<tests::fakes::derp::FakeConnection*> Derps;
    std::unique_ptr<ipn::ipnlocal::NativeNode> Subject;
};

TEST_F(Given_NativeNode, When_NetworkHasNoPeers_Then_StartsLocalServicesAndHomeDerp)
{
    Start();

    EXPECT_TRUE(Device().Opened);
    EXPECT_EQ(Services.Updates, 1);
    EXPECT_EQ(Regions, std::vector<int>{1});
    EXPECT_EQ(Subject->Network().SelfAddress(), Network.SelfAddress());
}

TEST_F(Given_NativeNode, When_HostQueriesQuad100_Then_AnswersWithoutAnyPeer)
{
    Start();
    const auto query = net::packet::Ipv4UdpDatagram::Build(
        net::Ipv4Address::Parse(Network.SelfAddress()).HostOrder(),
        net::dns::MagicDnsIpv4Address,
        12345,
        net::dns::DnsPort,
        net::dns::DnsQuery::Build("self.example.ts.net", 7));
    Device().Incoming.push_back(
        {.Result = wgengine::tstun::DeviceIoResult::Complete, .Packet = query});
    Events().Post({.Token = DeviceToken, .Readiness = base::EventReadiness::Readable});

    const auto result = Wait();
    ASSERT_EQ(Device().Written.size(), 1U);
    const auto response = net::packet::Ipv4UdpDatagram::Parse(Device().Written.front());
    ASSERT_TRUE(response);
    const auto answer = net::dns::DnsAnswer::Parse(response->Payload(), 7, "self.example.ts.net");

    EXPECT_TRUE(result.Transport.Packets.empty());
    EXPECT_EQ(answer.Addresses(), std::vector<std::string>{Network.SelfAddress()});
    EXPECT_EQ(response->Source(), net::dns::MagicDnsIpv4Address);
}

TEST_F(Given_NativeNode, When_LocalServiceProducesOutput_Then_PollDeliversItWithoutRemoteTraffic)
{
    Start();
    Services.Output.push_back({.Peer = std::nullopt, .Bytes = {1, 2, 3}});

    Subject->Poll(MaximumPackets);

    EXPECT_EQ(Device().Written, (std::vector<std::vector<std::uint8_t>>{{1, 2, 3}}));
    EXPECT_EQ(Services.Polls, 1);
}

TEST_F(Given_NativeNode, When_PacketDeviceBackpressures_Then_RetainsLocalOutputUntilWritable)
{
    Start();
    Device().WriteResult = wgengine::tstun::DeviceIoResult::WouldBlock;
    Services.Output.push_back({.Peer = std::nullopt, .Bytes = {1, 2, 3}});

    Subject->Poll(MaximumPackets);
    const auto retained = Device().WriteInterest && Device().Written.empty();
    Device().WriteResult = wgengine::tstun::DeviceIoResult::Complete;
    Events().Post({.Token = DeviceToken, .Readiness = base::EventReadiness::Writable});
    const auto result = Wait();

    EXPECT_TRUE(retained);
    EXPECT_EQ(Device().Written, (std::vector<std::vector<std::uint8_t>>{{1, 2, 3}}));
    EXPECT_FALSE(Device().WriteInterest);
    EXPECT_TRUE(result.Transport.Failures.empty());
}

TEST_F(Given_NativeNode, When_NetworkAddsDerpRegion_Then_UpdatesServicesAndTransports)
{
    Start();
    auto updated = Network;
    types::netmap::PeerConfig peer;
    peer.DerpRegion(2);
    peer.DerpHost("other.example.com");
    updated.Peers({peer});

    Subject->UpdateNetwork(updated);

    EXPECT_EQ(Regions, (std::vector<int>{1, 2}));
    EXPECT_EQ(Services.Updates, 2);
    EXPECT_EQ(Subject->Network().Peers().size(), 1U);
}

TEST_F(Given_NativeNode, When_NetworkChangesIdentity_Then_RejectsBeforeChangingState)
{
    Start();
    auto updated = Network;
    updated.SelfKey("nodekey:" + std::string(64, '1'));

    EXPECT_THROW(Subject->UpdateNetwork(updated), ipn::ipnlocal::NodeError);
    EXPECT_EQ(Subject->Network().SelfKey(), Network.SelfKey());
    EXPECT_EQ(Services.Updates, 1);
    EXPECT_EQ(Regions.size(), 1U);
}

TEST_F(Given_NativeNode, When_TransportOwnerRetires_Then_SharedLocalServicesStayAlive)
{
    Start();

    Subject.reset();

    EXPECT_EQ(Services.Stops, 0);
}

TEST_F(Given_NativeNode, When_HostTargetsPeer_Then_SendsWireGuardThroughDerp)
{
    Network.Peers({Peer()});
    Start();
    const auto packet = net::packet::Ipv4UdpDatagram::Build(
        net::Ipv4Address::Parse(Network.SelfAddress()).HostOrder(),
        net::Ipv4Address::Parse(Peer().Address()).HostOrder(),
        12345,
        23456,
        {1, 2, 3});
    Device().Incoming.push_back(
        {.Result = wgengine::tstun::DeviceIoResult::Complete, .Packet = packet});
    Events().Post({.Token = DeviceToken, .Readiness = base::EventReadiness::Readable});
    ASSERT_EQ(Derps.size(), 1U);

    const auto result = Wait();
    ASSERT_FALSE(Derps.front()->Sent.empty());

    EXPECT_NE(Derps.front()->Sent.front().Payload, packet);
    EXPECT_TRUE(
        wgengine::wireguard::WireGuardTunnel::IsPacket(Derps.front()->Sent.front().Payload));
    EXPECT_TRUE(result.Transport.Packets.empty());
}

TEST_F(Given_NativeNode, When_PingDeadlinePassesWithoutTraffic_Then_ExpiresPendingPing)
{
    Network.Peers({Peer()});
    Start();
    auto& tracker = Injector.create<wgengine::ping::Tracker&>();
    auto& time =
        dynamic_cast<tests::fakes::FakeTimeProvider&>(Injector.create<base::TimeProvider&>());
    wgengine::ping::Request request;
    request.Id = 7;
    request.Target = Peer().Address();
    request.PingMode = wgengine::ping::Mode::Tsmp;
    request.Timeout = std::chrono::seconds(1);
    const auto started = tracker.Start(request, Network, {}, time.Now());
    ASSERT_EQ(started.Status, wgengine::ping::StartStatus::Ready);
    time.Advance(std::chrono::seconds(2));

    const auto result = Wait();
    ASSERT_EQ(result.Received.size(), 1U);
    ASSERT_TRUE(result.Received.front().Ping);

    EXPECT_EQ(result.Received.front().Ping->RequestId, request.Id);
    EXPECT_FALSE(result.Received.front().Ping->Responded);
    EXPECT_FALSE(tracker.NextDeadline());
}

TEST_F(Given_NativeNode, When_PingTargetIsMissing_Then_DoesNotSend)
{
    Start();

    const auto status =
        Subject->StartPing({.Id = 1, .Target = "missing.example.ts.net", .Relay = {}});

    EXPECT_EQ(status, wgengine::ping::StartStatus::NoMatchingPeer);
    EXPECT_TRUE(Derps.front()->Sent.empty());
}

TEST_F(Given_NativeNode, When_PingTimesOut_Then_ReturnsCorrelatedCompletion)
{
    auto peer = Peer();
    const auto discoKey = crypto::GeneratePrivateKey();
    peer.DiscoKey("discokey:" + crypto::BytesToHex(discoKey.data(), discoKey.size()));
    Network.Peers({peer});
    Start();
    ASSERT_EQ(
        Subject->StartPing(
            {.Id = 17, .Target = peer.Name(), .Timeout = std::chrono::seconds(2), .Relay = {}}),
        wgengine::ping::StartStatus::Ready);
    auto& time =
        dynamic_cast<tests::fakes::FakeTimeProvider&>(Injector.create<base::TimeProvider&>());

    time.Advance(std::chrono::seconds(3));
    const auto result = Wait();
    ASSERT_EQ(result.Received.size(), 1U);
    ASSERT_TRUE(result.Received.front().Ping);

    EXPECT_EQ(result.Received.front().Ping->RequestId, 17U);
    EXPECT_FALSE(result.Received.front().Ping->Responded);
    EXPECT_FALSE(result.Received.front().DirectSource);
}

TEST_F(Given_NativeNode, When_DiscoPongArrivesDirectly_Then_ReportsAuthenticatedSourceAndLatency)
{
    const auto endpoint = net::Endpoint::Parse("192.0.2.2:1234");
    crypto::Bytes32 remoteNodeKey;
    remoteNodeKey.fill(0x11);
    disco::Disco remote(crypto::GeneratePrivateKey(), remoteNodeKey);
    auto peer = Peer();
    peer.DiscoKey("discokey:" +
                  crypto::BytesToHex(remote.PublicKey().data(), remote.PublicKey().size()));
    Network.Peers({peer});
    Start();
    ASSERT_EQ(Subject->StartPing({.Id = 31, .Target = peer.Name(), .Relay = {}}),
              wgengine::ping::StartStatus::Ready);
    ASSERT_FALSE(Derps.front()->Sent.empty());
    const auto ping = remote.Parse(Derps.front()->Sent.back().Payload);
    ASSERT_TRUE(ping);
    const auto pong = remote.BuildPong(crypto::X25519PublicFromPrivate(Options.DiscoPrivateKey),
                                       ping->Transaction,
                                       endpoint.Address(),
                                       endpoint.Port());
    auto& sockets = dynamic_cast<tests::fakes::FakeUdpSocketFactory&>(
        Injector.create<types::nettype::UdpSocketFactory&>());
    ASSERT_EQ(sockets.States.size(), 1U);
    auto& time =
        dynamic_cast<tests::fakes::FakeTimeProvider&>(Injector.create<base::TimeProvider&>());

    time.Advance(std::chrono::milliseconds(15));
    sockets.States.front()->Incoming.push_back({.Result = types::nettype::SocketIoResult::Complete,
                                                .Datagram = {.Source = endpoint, .Payload = pong}});
    Events().Post({.Token = UdpToken, .Readiness = base::EventReadiness::Readable});
    const auto result = Wait();
    ASSERT_EQ(result.Received.size(), 1U);
    ASSERT_TRUE(result.Received.front().Ping);

    EXPECT_EQ(result.Received.front().Ping->RequestId, 31U);
    EXPECT_TRUE(result.Received.front().Ping->Responded);
    EXPECT_EQ(result.Received.front().Ping->Latency, std::chrono::milliseconds(15));
    EXPECT_EQ(result.Received.front().DirectSource, endpoint);
}

TEST_F(Given_NativeNode, When_UdpFails_Then_Quad100AndDerpContinueWithoutClosingDevice)
{
    Network.Peers({Peer()});
    Start();
    const auto source = net::Ipv4Address::Parse(Network.SelfAddress()).HostOrder();
    const auto dns =
        net::packet::Ipv4UdpDatagram::Build(source,
                                            net::dns::MagicDnsIpv4Address,
                                            12345,
                                            net::dns::DnsPort,
                                            net::dns::DnsQuery::Build("self.example.ts.net", 9));
    const auto peerPacket = net::packet::Ipv4UdpDatagram::Build(
        source, net::Ipv4Address::Parse(Peer().Address()).HostOrder(), 12345, 23456, {7});
    Device().Incoming.push_back(
        {.Result = wgengine::tstun::DeviceIoResult::Complete, .Packet = dns});
    Device().Incoming.push_back(
        {.Result = wgengine::tstun::DeviceIoResult::Complete, .Packet = peerPacket});
    Events().Post({.Token = UdpToken, .Readiness = base::EventReadiness::Error});
    Events().Post({.Token = DeviceToken, .Readiness = base::EventReadiness::Readable});

    const auto result = Wait();
    ASSERT_EQ(Device().Written.size(), 1U);
    const auto response = net::packet::Ipv4UdpDatagram::Parse(Device().Written.front());
    ASSERT_TRUE(response);
    const auto answer = net::dns::DnsAnswer::Parse(response->Payload(), 9, "self.example.ts.net");
    ASSERT_FALSE(Derps.front()->Sent.empty());

    EXPECT_EQ(result.Transport.Failures.size(), 1U);
    EXPECT_EQ(answer.Addresses(), std::vector<std::string>{Network.SelfAddress()});
    EXPECT_TRUE(
        wgengine::wireguard::WireGuardTunnel::IsPacket(Derps.front()->Sent.front().Payload));
    EXPECT_EQ(Regions, std::vector<int>{1});
    EXPECT_EQ(Services.Stops, 0);
    EXPECT_FALSE(Device().Closed);
}

TEST_F(Given_NativeNode, When_UdpRebindCompletes_Then_ReplacesOnlyTheFailedSocket)
{
    Start();
    auto& sockets = dynamic_cast<tests::fakes::FakeUdpSocketFactory&>(
        Injector.create<types::nettype::UdpSocketFactory&>());
    auto& time =
        dynamic_cast<tests::fakes::FakeTimeProvider&>(Injector.create<base::TimeProvider&>());
    auto& protocol = Injector.create<wgengine::PeerProtocol&>();
    auto* router = &protocol.Router();
    Events().Post({.Token = UdpToken, .Readiness = base::EventReadiness::Closed});

    const auto failed = Wait();
    Subject->Poll(MaximumPackets);
    const auto beforeRetry = sockets.States.size();
    time.Advance(std::chrono::seconds(1));
    Subject->Poll(MaximumPackets);
    const auto rebound = Wait();
    ASSERT_EQ(sockets.States.size(), 2U);
    ASSERT_TRUE(rebound.Endpoints);

    EXPECT_EQ(failed.Transport.Failures.size(), 1U);
    EXPECT_EQ(beforeRetry, 1U);
    EXPECT_TRUE(sockets.States.front()->Closed);
    EXPECT_FALSE(sockets.States.back()->Closed);
    EXPECT_EQ(rebound.Endpoints->BoundEndpoint, sockets.States.back()->LocalEndpoint);
    EXPECT_EQ(&protocol.Router(), router);
    EXPECT_EQ(Regions, std::vector<int>{1});
    EXPECT_EQ(Services.Stops, 0);
    EXPECT_FALSE(Device().Closed);
}

TEST_F(Given_NativeNode, When_ReplacementBindFails_Then_BacksOffWhileLocalServicesRemainUsable)
{
    Start();
    auto& sockets = dynamic_cast<tests::fakes::FakeUdpSocketFactory&>(
        Injector.create<types::nettype::UdpSocketFactory&>());
    auto& time =
        dynamic_cast<tests::fakes::FakeTimeProvider&>(Injector.create<base::TimeProvider&>());
    Events().Post({.Token = UdpToken, .Readiness = base::EventReadiness::Error});

    (void)Wait();
    time.Advance(std::chrono::seconds(1));
    Subject->Poll(MaximumPackets);
    Events().Post({.Token = UdpToken, .Readiness = base::EventReadiness::Error});
    (void)Wait();
    time.Advance(std::chrono::seconds(1));
    Services.Output.push_back({.Peer = std::nullopt, .Bytes = {8, 9}});
    Subject->Poll(MaximumPackets);
    const auto beforeRetry = sockets.States.size();
    time.Advance(std::chrono::seconds(1));
    Subject->Poll(MaximumPackets);
    const auto rebound = Wait();

    EXPECT_EQ(beforeRetry, 2U);
    EXPECT_EQ(sockets.States.size(), 3U);
    EXPECT_TRUE(rebound.Endpoints);
    EXPECT_EQ(Device().Written, (std::vector<std::vector<std::uint8_t>>{{8, 9}}));
    EXPECT_EQ(Services.Stops, 0);
}

TEST_F(Given_NativeNode, When_ReplacementBindNeverCompletes_Then_DeadlineRetiresItAndSchedulesRetry)
{
    Start();
    auto& sockets = dynamic_cast<tests::fakes::FakeUdpSocketFactory&>(
        Injector.create<types::nettype::UdpSocketFactory&>());
    auto& time =
        dynamic_cast<tests::fakes::FakeTimeProvider&>(Injector.create<base::TimeProvider&>());
    Events().Post({.Token = UdpToken, .Readiness = base::EventReadiness::Error});

    (void)Wait();
    time.Advance(std::chrono::seconds(1));
    Subject->Poll(MaximumPackets);
    ASSERT_EQ(sockets.States.size(), 2U);
    sockets.States.back()->LocalEndpoint = {};
    time.Advance(std::chrono::seconds(10));
    Subject->Poll(MaximumPackets);
    const auto timedOut = sockets.States.back()->Closed;
    const auto beforeRetry = sockets.States.size();
    time.Advance(std::chrono::seconds(2));
    Subject->Poll(MaximumPackets);
    const auto rebound = Wait();

    EXPECT_TRUE(timedOut);
    EXPECT_EQ(beforeRetry, 2U);
    EXPECT_EQ(sockets.States.size(), 3U);
    EXPECT_TRUE(rebound.Endpoints);
    EXPECT_EQ(Services.Stops, 0);
    EXPECT_FALSE(Device().Closed);
}

TEST_F(Given_NativeNode, When_ReplacementOpenFailsSynchronously_Then_RetryUsesBackoff)
{
    Start();
    auto& sockets = dynamic_cast<tests::fakes::FakeUdpSocketFactory&>(
        Injector.create<types::nettype::UdpSocketFactory&>());
    auto& time =
        dynamic_cast<tests::fakes::FakeTimeProvider&>(Injector.create<base::TimeProvider&>());
    sockets.FailOpen = true;
    Events().Post({.Token = UdpToken, .Readiness = base::EventReadiness::Error});

    (void)Wait();
    time.Advance(std::chrono::seconds(1));
    Subject->Poll(MaximumPackets);
    time.Advance(std::chrono::seconds(1));
    Subject->Poll(MaximumPackets);
    const auto attemptsBeforeRetry = sockets.Options.size();
    sockets.FailOpen = false;
    time.Advance(std::chrono::seconds(1));
    Subject->Poll(MaximumPackets);
    const auto rebound = Wait();

    EXPECT_EQ(attemptsBeforeRetry, 2U);
    EXPECT_EQ(sockets.Options.size(), 3U);
    EXPECT_TRUE(rebound.Endpoints);
    EXPECT_EQ(Services.Stops, 0);
    EXPECT_FALSE(Device().Closed);
}

TEST_F(Given_NativeNode, When_RecoveryTokenIsMissing_Then_RejectsBeforeOpeningPacketDevice)
{
    const wgengine::tstun::DeviceOptions device{.Name = "test", .ReadinessToken = DeviceToken};

    EXPECT_THROW(Subject->Start(Network, Options, device, {}), ipn::ipnlocal::NodeError);
    EXPECT_FALSE(Device().Opened);
    EXPECT_TRUE(Regions.empty());
}

TEST_F(Given_NativeNode,
       When_UdpIsReplaced_Then_EstablishedWireGuardSessionStillDecryptsPeerTraffic)
{
    const auto privateKey = crypto::GeneratePrivateKey();
    const auto publicKey = crypto::X25519PublicFromPrivate(privateKey);
    auto peer = Peer();
    peer.Key("nodekey:" + crypto::BytesToHex(publicKey.data(), publicKey.size()));
    Network.Peers({peer});
    Start();
    wgengine::wireguard::WireGuardTunnel remote(privateKey);
    const auto remotePeer = remote.AddPeer(Options.NodePublicKey);
    auto& router = Injector.create<wgengine::PeerProtocol&>().Router();
    const auto handshake = router.Receive(publicKey, remote.CreateHandshake(remotePeer));
    ASSERT_EQ(handshake.Outbound.size(), 1U);
    ASSERT_TRUE(remote.ProcessPacket(remotePeer, handshake.Outbound.front().Payload));
    ASSERT_TRUE(router.Receive(publicKey, remote.Encrypt(remotePeer, {})).Accepted);
    ASSERT_TRUE(router.HasSession(publicKey));
    const auto plaintext = net::packet::Ipv4UdpDatagram::Build(
        net::Ipv4Address::Parse(peer.Address()).HostOrder(),
        net::Ipv4Address::Parse(Network.SelfAddress()).HostOrder(),
        23456,
        12345,
        {5, 6, 7});
    const auto encrypted = remote.Encrypt(remotePeer, plaintext);
    auto& sockets = dynamic_cast<tests::fakes::FakeUdpSocketFactory&>(
        Injector.create<types::nettype::UdpSocketFactory&>());
    auto& time =
        dynamic_cast<tests::fakes::FakeTimeProvider&>(Injector.create<base::TimeProvider&>());
    Events().Post({.Token = UdpToken, .Readiness = base::EventReadiness::Error});

    (void)Wait();
    time.Advance(std::chrono::seconds(1));
    Subject->Poll(MaximumPackets);
    const auto rebound = Wait();
    ASSERT_EQ(sockets.States.size(), 2U);
    sockets.States.back()->Incoming.push_back(
        {.Result = types::nettype::SocketIoResult::Complete,
         .Datagram = {.Source = net::Endpoint::Parse("192.0.2.2:1234"), .Payload = encrypted}});
    Events().Post({.Token = UdpToken, .Readiness = base::EventReadiness::Readable});
    (void)Wait();

    EXPECT_TRUE(rebound.Endpoints);
    EXPECT_TRUE(router.HasSession(publicKey));
    EXPECT_EQ(Device().Written, (std::vector<std::vector<std::uint8_t>>{plaintext}));
    EXPECT_EQ(Services.Stops, 0);
    EXPECT_EQ(Regions, std::vector<int>{1});
}

TEST_F(Given_NativeNode, When_ReboundStunResponds_Then_PublishesNewMappingWhileServingLocalTraffic)
{
    const auto server = net::Endpoint::Parse("192.0.2.20:3478");
    Start(server);
    auto& sockets = dynamic_cast<tests::fakes::FakeUdpSocketFactory&>(
        Injector.create<types::nettype::UdpSocketFactory&>());
    auto& time =
        dynamic_cast<tests::fakes::FakeTimeProvider&>(Injector.create<base::TimeProvider&>());
    Events().Post({.Token = UdpToken, .Readiness = base::EventReadiness::Error});

    (void)Wait();
    time.Advance(std::chrono::seconds(1));
    Subject->Poll(MaximumPackets);
    const auto rebound = Wait();
    ASSERT_EQ(sockets.States.size(), 2U);
    auto& socket = *sockets.States.back();
    socket.OnSend = [&](const net::Endpoint&, const std::vector<std::uint8_t>& request)
    {
        std::vector<std::uint8_t> response{0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42,
                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x08,
                                           0x00, 0x01, 0x83, 0xbb, 0xe1, 0x12, 0xa6, 0x48};
        std::copy_n(request.begin() + 8, 12, response.begin() + 8);
        socket.Incoming.push_back({.Result = types::nettype::SocketIoResult::Complete,
                                   .Datagram = {.Source = server, .Payload = std::move(response)}});
        Events().Post({.Token = UdpToken, .Readiness = base::EventReadiness::Readable});
    };
    Services.Output.push_back({.Peer = std::nullopt, .Bytes = {8, 9}});
    const auto discovered = Wait();
    ASSERT_TRUE(rebound.Endpoints);
    ASSERT_TRUE(discovered.Endpoints);
    ASSERT_EQ(socket.Sent.size(), 1U);

    EXPECT_FALSE(rebound.Endpoints->PublicEndpoint);
    EXPECT_EQ(discovered.Endpoints->BoundEndpoint, socket.LocalEndpoint);
    EXPECT_EQ(discovered.Endpoints->PublicEndpoint, net::Endpoint::Parse("192.0.2.10:41641"));
    EXPECT_EQ(socket.Sent.front().Destination, server);
    EXPECT_TRUE(discovered.Transport.Datagrams.empty());
    EXPECT_EQ(Device().Written, (std::vector<std::vector<std::uint8_t>>{{8, 9}}));
    EXPECT_EQ(Services.Stops, 0);
    EXPECT_FALSE(Device().Closed);
    EXPECT_EQ(Regions, std::vector<int>{1});
}

TEST_F(Given_NativeNode, When_ReboundStunTimesOut_Then_KeepsReplacementAndServicesAlive)
{
    Start(net::Endpoint::Parse("192.0.2.20:3478"));
    auto& sockets = dynamic_cast<tests::fakes::FakeUdpSocketFactory&>(
        Injector.create<types::nettype::UdpSocketFactory&>());
    auto& time =
        dynamic_cast<tests::fakes::FakeTimeProvider&>(Injector.create<base::TimeProvider&>());
    Events().Post({.Token = UdpToken, .Readiness = base::EventReadiness::Error});

    (void)Wait();
    time.Advance(std::chrono::seconds(1));
    Subject->Poll(MaximumPackets);
    const auto rebound = Wait();
    (void)Wait();
    time.Advance(std::chrono::seconds(3));
    Services.Output.push_back({.Peer = std::nullopt, .Bytes = {3, 4}});
    const auto expired = Wait();
    ASSERT_TRUE(expired.Transport.EndpointDiscovery);
    ASSERT_EQ(sockets.States.size(), 2U);

    EXPECT_TRUE(rebound.Endpoints);
    EXPECT_FALSE(expired.Endpoints);
    EXPECT_FALSE(expired.Transport.EndpointDiscovery->Endpoint);
    EXPECT_FALSE(sockets.States.back()->Closed);
    EXPECT_EQ(Device().Written, (std::vector<std::vector<std::uint8_t>>{{3, 4}}));
    EXPECT_EQ(Services.Stops, 0);
    EXPECT_FALSE(Device().Closed);
}

} // namespace

TEST_F(Given_NativeNode,
       When_LoopbackResolverQueriesMagicDns_Then_ResponseReturnsWithoutPeerTransport)
{
    Network.DnsResolver("100.100.100.100");
    Network.DnsRoutes({{"example.ts.net", {}}});
    Start();
    const auto client = net::Endpoint::Parse("127.0.0.1:12000");
    const auto query = net::dns::DnsQuery::Build("self.example.ts.net", 42);

    const auto forward = Subject->ForwardDns(client, query, {"192.0.2.53"});

    EXPECT_EQ(forward.Status, ipn::ipnlocal::DnsForwardStatus::Ready);
    EXPECT_TRUE(forward.LocalReply.has_value());
    EXPECT_EQ(forward.LocalReply.value().Client, client);
    EXPECT_EQ(forward.LocalReply.value().Payload.at(0), query.at(0));
    EXPECT_EQ(forward.LocalReply.value().Payload.at(1), query.at(1));
    EXPECT_TRUE(Derps.at(0)->Sent.empty());
}

TEST_F(Given_NativeNode, When_PeerRegionIsStillAuthenticating_Then_OwnershipIsNotReady)
{
    auto peer = Peer();
    peer.DerpRegion(2);
    peer.DerpHost("other.example.com");
    Network.Peers({peer});
    Start();
    ASSERT_EQ(Derps.size(), 2U);
    Derps.back()->Authenticated = false;

    const auto ready = Subject->OwnershipReady();

    EXPECT_TRUE(Subject->Connected());
    EXPECT_FALSE(ready);
}

TEST_F(Given_NativeNode, When_RequiredPeerRegionIsMissing_Then_OwnershipIsNotReady)
{
    auto peer = Peer();
    peer.DerpRegion(2);
    peer.DerpHost("");
    Network.Peers({peer});
    Start();

    const auto ready = Subject->OwnershipReady();

    EXPECT_TRUE(Subject->Connected());
    EXPECT_FALSE(ready);
}

TEST_F(Given_NativeNode, When_AllRequiredRegionsAuthenticate_Then_OwnershipIsReady)
{
    auto peer = Peer();
    peer.DerpRegion(2);
    peer.DerpHost("other.example.com");
    Network.Peers({peer});
    Start();

    const auto ready = Subject->OwnershipReady();

    EXPECT_TRUE(ready);
    EXPECT_EQ(Derps.size(), 2U);
}

} // namespace tailgate
