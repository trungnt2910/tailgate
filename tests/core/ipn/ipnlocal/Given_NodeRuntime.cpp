#include <chrono>
#include <optional>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/ipn/ipnlocal/NodeRuntime.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/net/packet/Tsmp.h>

#include "wgengine/ping/impl/TrackerImpl.h"

#include "fakes/crypto/FakeRandom.h"
#include "fakes/ipn/ipnlocal/FakeLocalServices.h"

namespace tailgate
{
namespace
{

using namespace std::chrono_literals;
using ipn::ipnlocal::NodeRuntime;
using ipn::ipnlocal::PacketDelivery;
using net::Ipv4Address;
using net::packet::Ipv4UdpDatagram;
using net::packet::TsmpPacket;
constexpr auto SelfAddress = Ipv4Address::FromOctets(100, 64, 0, 1);
constexpr auto PeerAddress = Ipv4Address::FromOctets(100, 64, 0, 2);
constexpr std::uint16_t PeerApiPort = 41112;

using Services = tests::fakes::FakeLocalServices;

struct Output
{
    PacketDelivery Delivery()
    {
        return {
            .Host =
                [this](auto packet)
            {
                Host.push_back(std::move(packet));
                return Available;
            },
            .Network =
                [this](const auto& packet)
            {
                Network.push_back(packet);
            },
            .Peer =
                [this](const auto& peer, const auto& packet)
            {
                Peer = peer;
                PeerPackets.push_back(packet);
            },
        };
    }

    bool Available = true;
    std::vector<std::vector<std::uint8_t>> Host;
    std::vector<std::vector<std::uint8_t>> Network;
    std::vector<std::vector<std::uint8_t>> PeerPackets;
    crypto::Bytes32 Peer{};
};

class Given_NodeRuntime : public testing::Test
{
protected:
    Given_NodeRuntime()
    {
        Peer.front() = 1;
        types::netmap::PeerConfig peer;
        peer.Name("peer.example.ts.net");
        peer.Address(PeerAddress.ToString());
        peer.Key("nodekey:" + crypto::BytesToHex(Peer.data(), Peer.size()));
        peer.AllowedPrefixes({net::packet::Ipv4Prefix::Parse("100.64.0.2/32").value()});
        Network.SelfAddress(SelfAddress.ToString());
        Network.Peers({peer});
        Network.DnsResolver("100.100.100.100");
        Runtime.SetNetworkConfig(Network);
    }

    Services Local;
    tests::fakes::FakeRandom Random{{0x12, 0x34}};
    ipn::ipnlocal::DnsForwarder Dns{Random};
    wgengine::ping::impl::TrackerImpl Pings;
    NodeRuntime Runtime{Local, Dns, Pings};
    crypto::Bytes32 Peer{};
    types::netmap::NetworkConfig Network;
    Output OldPath;
    Output NewPath;
};

TEST_F(Given_NodeRuntime, When_HostPacketIsLocal_Then_TransportIsNotNeeded)
{
    Local.ConsumeHost = true;
    const std::vector<std::uint8_t> packet{1, 2, 3};

    Runtime.HandleHostPacket(packet, OldPath.Delivery());

    EXPECT_TRUE(OldPath.Network.empty());
    EXPECT_TRUE(OldPath.PeerPackets.empty());
}

TEST_F(Given_NodeRuntime, When_HostPathChanges_Then_PacketsUseNewDelivery)
{
    const auto packet = Ipv4UdpDatagram::Build(
        SelfAddress.HostOrder(), PeerAddress.HostOrder(), 1234, 4321, {1, 2, 3});
    Runtime.HandleHostPacket(packet, OldPath.Delivery());

    Runtime.HandleHostPacket(packet, NewPath.Delivery());

    EXPECT_EQ(OldPath.Network, (std::vector<std::vector<std::uint8_t>>{packet}));
    EXPECT_EQ(NewPath.Network, (std::vector<std::vector<std::uint8_t>>{packet}));
    EXPECT_EQ(Local.Stops, 0);
}

TEST_F(Given_NodeRuntime, When_PeerPacketIsLocal_Then_AuthenticatedIdentityReachesService)
{
    Local.ConsumePeer = true;
    const auto ping = TsmpPacket::BuildPing(PeerAddress.HostOrder(), SelfAddress.HostOrder(), {});

    const auto result = Runtime.HandlePeerPacket(Peer, ping, {}, OldPath.Delivery());

    EXPECT_EQ(Local.AuthenticatedPeer, Peer);
    EXPECT_TRUE(OldPath.Host.empty());
    EXPECT_TRUE(OldPath.PeerPackets.empty());
    EXPECT_TRUE(result.HostAvailable);
}

TEST_F(Given_NodeRuntime, When_TsmpPingArrives_Then_ReplyUsesAuthenticatedPeerAndConfiguredPort)
{
    Runtime.SetPeerApiPort(PeerApiPort);
    const auto ping = TsmpPacket::BuildPing(PeerAddress.HostOrder(), SelfAddress.HostOrder(), {});
    const auto expected = TsmpPacket::BuildPong(ping, PeerApiPort);
    ASSERT_TRUE(expected.has_value());

    const auto result = Runtime.HandlePeerPacket(Peer, ping, {}, NewPath.Delivery());

    EXPECT_EQ(NewPath.Peer, Peer);
    EXPECT_EQ(NewPath.PeerPackets, (std::vector<std::vector<std::uint8_t>>{*expected}));
    EXPECT_TRUE(NewPath.Network.empty());
    EXPECT_TRUE(NewPath.Host.empty());
    EXPECT_FALSE(result.Ping.has_value());
}

TEST_F(Given_NodeRuntime, When_ResponderIsDisabled_Then_TsmpPingReachesHost)
{
    Runtime.SetPeerApiPort(std::nullopt);
    const auto ping = TsmpPacket::BuildPing(PeerAddress.HostOrder(), SelfAddress.HostOrder(), {});

    const auto result = Runtime.HandlePeerPacket(Peer, ping, {}, OldPath.Delivery());

    EXPECT_EQ(OldPath.Host, (std::vector<std::vector<std::uint8_t>>{ping}));
    EXPECT_TRUE(OldPath.PeerPackets.empty());
    EXPECT_TRUE(result.HostAvailable);
}

TEST_F(Given_NodeRuntime, When_TsmpCompletesAfterPathChange_Then_OriginalRequestSurvives)
{
    wgengine::ping::Request request;
    request.Id = 42;
    request.Target = "peer";
    request.PingMode = wgengine::ping::Mode::Tsmp;
    const auto started = Pings.Start(request, Network, {}, {});
    ASSERT_TRUE(started.Outbound.has_value());
    const auto pong = TsmpPacket::BuildPong(started.Outbound->Payload, PeerApiPort);
    ASSERT_TRUE(pong.has_value());
    Runtime.SetNetworkConfig(Network);

    const auto result = Runtime.HandlePeerPacket(
        Peer, *pong, base::TimeProvider::TimePoint(5ms), NewPath.Delivery());

    EXPECT_TRUE(result.Ping.has_value());
    EXPECT_EQ(result.Ping.value().RequestId, request.Id);
    EXPECT_EQ(result.Ping.value().Latency, 5ms);
    EXPECT_EQ(result.Ping.value().PeerApiPort, PeerApiPort);
    EXPECT_TRUE(NewPath.Host.empty());
    EXPECT_EQ(Local.Stops, 0);
}

TEST_F(Given_NodeRuntime, When_TunneledDnsCompletesAfterPathChange_Then_OriginalClientIsRetained)
{
    Network.DnsDefaultResolvers({PeerAddress.ToString()});
    ipn::ipnlocal::NetworkPolicy policy("");
    (void)policy.Apply(Network);
    const auto client = net::Endpoint::Parse("127.0.0.1:12345");
    const auto query = net::dns::DnsQuery::Build("host.example.com", 42);
    const auto pending = Dns.Begin(client, query, policy, {}, {});
    ASSERT_TRUE(pending.TunnelPacket.has_value());
    const auto response = Ipv4UdpDatagram::Build(
        PeerAddress.HostOrder(), SelfAddress.HostOrder(), 53, client.Port(), pending.Payload);
    Runtime.SetNetworkConfig(Network);

    const auto result = Runtime.HandlePeerPacket(Peer, response, {}, NewPath.Delivery());

    EXPECT_TRUE(result.Dns.has_value());
    EXPECT_EQ(result.Dns.value().Client, client);
    EXPECT_EQ(result.Dns.value().Payload, query);
    EXPECT_TRUE(NewPath.Host.empty());
    EXPECT_EQ(Local.Stops, 0);
}

TEST_F(Given_NodeRuntime, When_HostDeliveryFails_Then_RuntimeReportsUnavailable)
{
    NewPath.Available = false;
    const auto packet = Ipv4UdpDatagram::Build(
        PeerAddress.HostOrder(), SelfAddress.HostOrder(), 1234, 4321, {1, 2, 3});

    const auto result = Runtime.HandlePeerPacket(Peer, packet, {}, NewPath.Delivery());

    EXPECT_FALSE(result.HostAvailable);
    EXPECT_EQ(NewPath.Host, (std::vector<std::vector<std::uint8_t>>{packet}));
}

TEST_F(Given_NodeRuntime, When_LocalStreamProducesOutputAfterPathChange_Then_ItUsesNewPath)
{
    Local.Deadline = base::TimeProvider::TimePoint(1s);
    Local.Output = {{.Peer = Peer, .Bytes = {1}, .ForwardFromHost = false}};
    Runtime.Poll(1, OldPath.Delivery());
    Local.Output = {{.Peer = Peer, .Bytes = {2}, .ForwardFromHost = false}};

    Runtime.Poll(1, NewPath.Delivery());

    EXPECT_EQ(OldPath.PeerPackets, (std::vector<std::vector<std::uint8_t>>{{1}}));
    EXPECT_EQ(NewPath.PeerPackets, (std::vector<std::vector<std::uint8_t>>{{2}}));
    EXPECT_EQ(Local.Stops, 0);
    EXPECT_EQ(Runtime.NextDeadline(), Local.Deadline);
}

TEST_F(Given_NodeRuntime, When_MultipleSubsystemsHaveDeadlines_Then_EarliestWins)
{
    Network.DnsDefaultResolvers({"192.0.2.53"});
    ipn::ipnlocal::NetworkPolicy policy("");
    (void)policy.Apply(Network);
    const auto pending = Dns.Begin(net::Endpoint::Parse("127.0.0.1:12345"),
                                   net::dns::DnsQuery::Build("host.example.com", 42),
                                   policy,
                                   {},
                                   {});
    ASSERT_EQ(pending.Status, ipn::ipnlocal::DnsForwardStatus::Ready);
    wgengine::ping::Request request;
    request.Id = 1;
    request.Target = "peer";
    request.PingMode = wgengine::ping::Mode::Tsmp;
    request.Timeout = 5s;
    const auto started = Pings.Start(request, Network, {}, {});
    ASSERT_TRUE(started.Outbound.has_value());
    Local.Deadline = base::TimeProvider::TimePoint(1s);

    const auto localDeadline = Runtime.NextDeadline();
    Local.Deadline.reset();
    const auto pingDeadline = Runtime.NextDeadline();
    const auto expired = Pings.Expire(base::TimeProvider::TimePoint(5s));
    const auto dnsDeadline = Runtime.NextDeadline();

    EXPECT_EQ(localDeadline, base::TimeProvider::TimePoint(1s));
    EXPECT_EQ(pingDeadline, base::TimeProvider::TimePoint(5s));
    EXPECT_EQ(dnsDeadline, base::TimeProvider::TimePoint(10s));
    EXPECT_EQ(expired.size(), 1U);
}

} // namespace

TEST_F(Given_NodeRuntime, When_HostQueriesMagicDns_Then_AnswersWithoutTransport)
{
    Network.MagicDnsDomain("example.ts.net");
    Runtime.SetNetworkConfig(Network);
    const auto query = Ipv4UdpDatagram::Build(SelfAddress.HostOrder(),
                                              net::dns::MagicDnsIpv4Address,
                                              12345,
                                              net::dns::DnsPort,
                                              net::dns::DnsQuery::Build("peer.example.ts.net", 7));

    Runtime.HandleHostPacket(query, OldPath.Delivery());
    ASSERT_EQ(OldPath.Host.size(), 1U);
    const auto response = Ipv4UdpDatagram::Parse(OldPath.Host.front());
    ASSERT_TRUE(response);
    const auto answer = net::dns::DnsAnswer::Parse(response->Payload(), 7, "peer.example.ts.net");

    EXPECT_EQ(answer.Addresses(), std::vector<std::string>{PeerAddress.ToString()});
    EXPECT_EQ(response->Source(), net::dns::MagicDnsIpv4Address);
    EXPECT_EQ(response->Destination(), SelfAddress.HostOrder());
    EXPECT_TRUE(OldPath.Network.empty());
    EXPECT_TRUE(OldPath.PeerPackets.empty());
}

TEST_F(Given_NodeRuntime, When_MagicDnsQuerySpoofsAnotherSource_Then_DropsIt)
{
    const auto query = Ipv4UdpDatagram::Build(PeerAddress.HostOrder(),
                                              net::dns::MagicDnsIpv4Address,
                                              12345,
                                              net::dns::DnsPort,
                                              net::dns::DnsQuery::Build("peer.example.ts.net", 7));

    Runtime.HandleHostPacket(query, OldPath.Delivery());

    EXPECT_TRUE(OldPath.Host.empty());
    EXPECT_TRUE(OldPath.Network.empty());
}

} // namespace tailgate
