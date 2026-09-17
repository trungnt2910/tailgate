#include <chrono>
#include <string_view>

#include <gtest/gtest.h>

#include <tailgate/ipn/ipnlocal/LocalServices.h>
#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/packet/Ipv4.h>

#include "fakes/di/FakeNetworkBindings.h"
#include "fakes/drive/FakeTcpStack.h"
#include "fakes/net/FragmentedPackets.h"

namespace tailgate::tests
{
namespace netstack = wgengine::netstack;

class Given_LocalServices : public testing::Test
{
protected:
    Given_LocalServices()
    {
        fakes::InstallFakeNetworkBindings(injector);
        injector.InstallSingleton<fakes::FakeTcpStack, netstack::Stack>();
        stack = injector.create<std::shared_ptr<fakes::FakeTcpStack>>();
        services = &injector.create<ipn::ipnlocal::LocalServices&>();
        config.SelfKey("nodekey:" + std::string(64, '1'));
        config.SelfAddresses({"192.0.2.1", "2001:db8::1"});
        config.Domain("example.ts.net");
        config.Capabilities({"drive:access"});
        peerKey.fill(0x22);
        types::netmap::PeerConfig peer;
        peer.Key("nodekey:" + crypto::BytesToHex(peerKey.data(), peerKey.size()));
        peer.Addresses({"192.0.2.2", "2001:db8::2"});
        config.Peers({peer});
        services->SetNetworkConfig(config);
    }

    static std::vector<std::uint8_t>
    Packet(const std::string& source, const std::string& destination, std::uint8_t protocol = 6)
    {
        return net::packet::Ipv4Packet::Build(net::Ipv4Address::Parse(source).HostOrder(),
                                              net::Ipv4Address::Parse(destination).HostOrder(),
                                              protocol,
                                              std::vector<std::uint8_t>(20));
    }

    di::Injector injector;
    std::shared_ptr<fakes::FakeTcpStack> stack;
    ipn::ipnlocal::LocalServices* services = nullptr;
    types::netmap::NetworkConfig config;
    crypto::Bytes32 peerKey{};
};

TEST_F(Given_LocalServices, When_Configured_Then_OnlyQuad100WebDavEndpointsAreListening)
{
    const auto expected4 = net::IpAddress::Parse("100.100.100.100");
    const auto expected6 = net::IpAddress::Parse("fd7a:115c:a1e0::53");

    const auto listeners = stack->Listening;
    ASSERT_EQ(listeners.size(), 2U);

    EXPECT_EQ(listeners.size(), 2U);
    EXPECT_EQ(listeners[0].Address, expected4);
    EXPECT_EQ(listeners[1].Address, expected6);
    EXPECT_EQ(listeners[0].Port, 8080);
    EXPECT_EQ(listeners[1].Port, 8080);
}

TEST_F(Given_LocalServices, When_LocalTcpAndDnsArrive_Then_OnlyTcpIsIntercepted)
{
    const auto tcp = Packet("192.0.2.1", "100.100.100.100");
    const auto dns = Packet("192.0.2.1", "100.100.100.100", 17);

    const auto tcpConsumed = services->HandleHostPacket(tcp);
    const auto dnsConsumed = services->HandleHostPacket(dns);
    ASSERT_EQ(stack->InputPackets.size(), 1U);

    EXPECT_TRUE(tcpConsumed);
    EXPECT_FALSE(dnsConsumed);
    EXPECT_EQ(stack->InputPackets.size(), 1U);
    EXPECT_EQ(stack->InputPackets.front().Path, netstack::PacketPath::Host);
}

TEST_F(Given_LocalServices, When_PeerClaimsAnotherNodeAddress_Then_PacketIsDroppedBeforeReassembly)
{
    const auto packet = Packet("192.0.2.2", "192.0.2.1");
    crypto::Bytes32 attacker{};
    attacker.fill(0x33);

    const auto consumed = services->HandlePeerPacket(attacker, packet);

    EXPECT_TRUE(consumed);
    EXPECT_TRUE(stack->InputPackets.empty());
}

TEST_F(Given_LocalServices, When_AuthenticatedNodeSendsTcp_Then_PeerInterfaceReceivesIt)
{
    const auto packet = Packet("192.0.2.2", "192.0.2.1");

    const auto consumed = services->HandlePeerPacket(peerKey, packet);
    ASSERT_EQ(stack->InputPackets.size(), 1U);

    EXPECT_TRUE(consumed);
    EXPECT_EQ(stack->InputPackets.size(), 1U);
    EXPECT_EQ(stack->InputPackets.front().Path, netstack::PacketPath::Peer);
    EXPECT_EQ(stack->InputPackets.front().Bytes, packet);
}

TEST_F(Given_LocalServices, When_ExitNodeReturnsInternetTraffic_Then_NormalHostPathIsPreserved)
{
    const auto packet = Packet("198.51.100.1", "192.0.2.1");

    const auto consumed = services->HandlePeerPacket(peerKey, packet);

    EXPECT_FALSE(consumed);
    EXPECT_TRUE(stack->InputPackets.empty());
}

TEST_F(Given_LocalServices, When_PeerTargetsQuad100_Then_LocalServiceCannotBeBorrowed)
{
    const auto packet = Packet("192.0.2.2", "100.100.100.100");

    const auto consumed = services->HandlePeerPacket(peerKey, packet);

    EXPECT_TRUE(consumed);
    EXPECT_TRUE(stack->InputPackets.empty());
}

TEST_F(Given_LocalServices, When_OutputTargetsPeerAndUnknownAddress_Then_OnlyNetmapPeerIsRouted)
{
    const auto known = Packet("192.0.2.1", "192.0.2.2");
    stack->Output.push_back({.Path = netstack::PacketPath::Peer, .Bytes = known});
    stack->Output.push_back(
        {.Path = netstack::PacketPath::Peer, .Bytes = Packet("192.0.2.1", "198.51.100.1")});

    const auto packets = services->TakeOutput(16);
    ASSERT_EQ(packets.size(), 1U);

    EXPECT_EQ(packets.size(), 1U);
    EXPECT_EQ(packets.front().Peer, peerKey);
    EXPECT_EQ(packets.front().Bytes, known);
}

TEST_F(Given_LocalServices, When_NodeIdentityChanges_Then_StackAndQueuedPacketsAreRetired)
{
    stack->Output.push_back(
        {.Path = netstack::PacketPath::Peer, .Bytes = Packet("192.0.2.1", "192.0.2.2")});
    config.SelfKey("nodekey:" + std::string(64, '3'));

    services->SetNetworkConfig(config);

    EXPECT_EQ(stack->Stops, 1U);
    EXPECT_EQ(stack->Starts, 2U);
    EXPECT_TRUE(stack->Output.empty());
}

TEST_F(Given_LocalServices, When_MapRefreshKeepsIdentity_Then_ExistingTcpStateSurvives)
{
    config.Peers({});

    services->SetNetworkConfig(config);

    EXPECT_EQ(stack->Stops, 0U);
    EXPECT_EQ(stack->Starts, 1U);
}

TEST_F(Given_LocalServices, When_PeerAddressIsReassigned_Then_QueuedOldPlaintextCannotReachNewOwner)
{
    stack->Output.push_back(
        {.Path = netstack::PacketPath::Peer, .Bytes = Packet("192.0.2.1", "192.0.2.2")});
    auto peers = config.Peers();
    peers.front().Key("nodekey:" + std::string(64, '3'));
    config.Peers(std::move(peers));

    services->SetNetworkConfig(config);
    const auto output = services->TakeOutput(16);

    EXPECT_EQ(stack->PeerInvalidations, 1U);
    EXPECT_EQ(stack->Stops, 0U);
    EXPECT_TRUE(output.empty());
}

TEST_F(Given_LocalServices, When_PeerAssignmentsDoNotChange_Then_PendingPacketStateIsPreserved)
{
    stack->Output.push_back(
        {.Path = netstack::PacketPath::Peer, .Bytes = Packet("192.0.2.1", "192.0.2.2")});

    services->SetNetworkConfig(config);
    const auto output = services->TakeOutput(16);
    ASSERT_EQ(output.size(), 1U);

    EXPECT_EQ(stack->PeerInvalidations, 0U);
    EXPECT_EQ(output.size(), 1U);
    EXPECT_EQ(output.front().Peer, peerKey);
}

TEST_F(Given_LocalServices, When_ConnectionIsAccepted_Then_CoreServesVirtualWebDav)
{
    auto state = std::make_shared<fakes::FakeTcpStreamState>();
    state->Input = "PROPFIND / HTTP/1.1\r\nHost: 100.100.100.100:8080\r\nDepth: "
                   "0\r\nContent-Length: 0\r\n\r\n";
    stack->Accepted.push_back(std::make_unique<fakes::FakeTcpStream>(state));

    services->Poll();

    EXPECT_TRUE(state->Output.starts_with("HTTP/1.1 207"));
    EXPECT_NE(state->Output.find("multistatus"), std::string::npos);
    EXPECT_FALSE(stack->Connected.has_value());
}

TEST_F(Given_LocalServices,
       When_HostIpv6FragmentsConcealTransport_Then_AllFragmentsReachSameReassembler)
{
    const auto packet = fakes::Ipv6UdpWithDestinationOptions(
        net::IpAddress::Parse("2001:db8::1"), net::IpAddress::Parse("fd7a:115c:a1e0::53"));
    const auto fragments = fakes::FragmentIpv6(packet);
    bool consumed = true;

    for (auto fragment = fragments.rbegin(); fragment != fragments.rend(); ++fragment)
    {
        consumed = services->HandleHostPacket(*fragment) && consumed;
    }

    EXPECT_TRUE(consumed);
    EXPECT_EQ(stack->InputPackets.size(), fragments.size());
    EXPECT_TRUE(std::ranges::all_of(stack->InputPackets,
                                    [](const auto& input)
                                    {
                                        return input.Path == netstack::PacketPath::Host;
                                    }));
}

TEST_F(Given_LocalServices,
       When_PeerIpv6FragmentsConcealTransport_Then_AllFragmentsReachSameReassembler)
{
    const auto packet = fakes::Ipv6UdpWithDestinationOptions(net::IpAddress::Parse("2001:db8::2"),
                                                             net::IpAddress::Parse("2001:db8::1"));
    const auto fragments = fakes::FragmentIpv6(packet);
    bool consumed = true;

    for (const auto& fragment : fragments)
    {
        consumed = services->HandlePeerPacket(peerKey, fragment) && consumed;
    }

    EXPECT_TRUE(consumed);
    EXPECT_EQ(stack->InputPackets.size(), fragments.size());
    EXPECT_TRUE(std::ranges::all_of(stack->InputPackets,
                                    [](const auto& input)
                                    {
                                        return input.Path == netstack::PacketPath::Peer;
                                    }));
}

TEST_F(Given_LocalServices, When_ReassembledHostPacketIsNotTcp_Then_OutputRetainsOutboundDirection)
{
    const auto packet = Packet("192.0.2.1", "100.100.100.100", 17);
    stack->Output.push_back({.Path = netstack::PacketPath::HostNetwork, .Bytes = packet});
    services->Poll();

    const auto deadline = services->NextDeadline();
    const auto output = services->TakeOutput(16);
    ASSERT_EQ(output.size(), 1U);

    EXPECT_EQ(deadline, injector.create<base::TimeProvider&>().Now());
    EXPECT_EQ(output.size(), 1U);
    EXPECT_TRUE(output.front().ForwardFromHost);
    EXPECT_FALSE(output.front().Peer.has_value());
    EXPECT_EQ(output.front().Bytes, packet);
}

TEST_F(Given_LocalServices, When_StartupWorkIsIdle_Then_NoImmediateDeadlineRemains)
{
    ASSERT_TRUE(services->NextDeadline().has_value());

    services->Poll();
    const auto deadline = services->NextDeadline();

    EXPECT_FALSE(deadline.has_value());
}

TEST_F(Given_LocalServices, When_OnlyTcpTimerRemains_Then_DeadlineIsNotReplacedByImmediateWork)
{
    const auto expected =
        injector.create<base::TimeProvider&>().Now() + std::chrono::milliseconds(250);
    stack->Deadline = expected;

    services->Poll();
    const auto deadline = services->NextDeadline();

    EXPECT_EQ(deadline, expected);
}

TEST_F(Given_LocalServices, When_PipelinedRequestsRemainReady_Then_PollYieldsWithWorkPending)
{
    auto state = std::make_shared<fakes::FakeTcpStreamState>();
    constexpr std::size_t RequestCount = 512;
    constexpr std::size_t MaximumReadAttemptsPerPoll = 16;
    constexpr std::string_view request = "OPTIONS / HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n";
    for (std::size_t index = 0; index < RequestCount; ++index)
    {
        state->Input += request;
    }
    std::size_t readAttempts = 0;
    state->CanRead = [&]
    {
        ++readAttempts;
        return true;
    };
    stack->Accepted.push_back(std::make_unique<fakes::FakeTcpStream>(state));
    const auto now = injector.create<base::TimeProvider&>().Now();

    services->Poll();
    const auto deadline = services->NextDeadline();

    EXPECT_TRUE(state->Output.starts_with("HTTP/1.1 200"));
    EXPECT_GT(readAttempts, 0U);
    EXPECT_LE(readAttempts, MaximumReadAttemptsPerPoll);
    EXPECT_EQ(deadline, now);
    EXPECT_FALSE(state->Closed);
    EXPECT_FALSE(state->Aborted);
}

TEST_F(Given_LocalServices, When_LocalResponseIsBackpressured_Then_PollDoesNotRequestImmediateRetry)
{
    auto state = std::make_shared<fakes::FakeTcpStreamState>();
    state->Input = "OPTIONS / HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n";
    state->WriteBlocked = true;
    std::size_t readAttempts = 0;
    state->CanRead = [&]
    {
        ++readAttempts;
        return true;
    };
    stack->Accepted.push_back(std::make_unique<fakes::FakeTcpStream>(state));
    services->Poll();
    ASSERT_GT(state->ReadOffset, 0U);
    readAttempts = 0;
    const auto expected =
        injector.create<base::TimeProvider&>().Now() + std::chrono::milliseconds(250);
    stack->Deadline = expected;

    services->Poll();
    const auto deadline = services->NextDeadline();

    EXPECT_EQ(readAttempts, 0U);
    EXPECT_EQ(deadline, expected);
    EXPECT_TRUE(state->Output.empty());
    EXPECT_FALSE(state->Aborted);
}

TEST_F(Given_LocalServices, When_LocalResponseUnblocks_Then_OutputResumesAndImmediateWorkClears)
{
    auto state = std::make_shared<fakes::FakeTcpStreamState>();
    state->Input = "OPTIONS / HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n";
    state->WriteBlocked = true;
    stack->Accepted.push_back(std::make_unique<fakes::FakeTcpStream>(state));
    services->Poll();
    ASSERT_GT(state->ReadOffset, 0U);
    ASSERT_TRUE(state->Output.empty());
    const auto now = injector.create<base::TimeProvider&>().Now();

    state->WriteBlocked = false;
    services->Poll();
    const auto deadline = services->NextDeadline();
    ASSERT_TRUE(deadline);

    EXPECT_TRUE(state->Output.starts_with("HTTP/1.1 200"));
    EXPECT_GT(*deadline, now);
    EXPECT_FALSE(state->Closed);
    EXPECT_FALSE(state->Aborted);
}

} // namespace tailgate::tests
