#include <chrono>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/ipn/ipnlocal/DnsForwarder.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/packet/Ipv4.h>

#include "fakes/crypto/FakeRandom.h"

namespace
{

using tailgate::ipn::ipnlocal::DnsForwarder;
using tailgate::ipn::ipnlocal::DnsForwardStatus;
using tailgate::ipn::ipnlocal::NetworkPolicy;
using tailgate::net::Endpoint;
using tailgate::net::Ipv4Address;
using tailgate::net::packet::Ipv4UdpDatagram;

class Given_DnsForwarder : public testing::Test
{
protected:
    Given_DnsForwarder()
    {
        Network.SelfAddress("100.64.0.1");
        Network.DnsResolver("100.100.100.100");
        (void)Policy.Apply(Network);
    }

    tailgate::types::netmap::NetworkConfig Network;
    NetworkPolicy Policy{""};
    tailgate::tests::fakes::FakeRandom Random{{0x12, 0x34}};
    DnsForwarder Forwarder{Random};
    const Endpoint Client = Endpoint::Parse("127.0.0.1:12345");
    const std::vector<std::string> Resolvers{"192.0.2.53"};
    const std::vector<std::uint8_t> Query =
        tailgate::net::dns::DnsQuery::Build("host.example.com", 42);
};

} // namespace

TEST_F(Given_DnsForwarder, When_ClientIdsCollide_Then_RepliesKeepTheirOriginalClients)
{
    const auto other = Endpoint::Parse("127.0.0.2:12345");
    const auto first = Forwarder.Begin(Client, Query, Policy, Resolvers, {});
    const auto second = Forwarder.Begin(other, Query, Policy, Resolvers, {});
    ASSERT_EQ(first.Status, DnsForwardStatus::Ready);
    ASSERT_EQ(second.Status, DnsForwardStatus::Ready);

    const auto secondReply = Forwarder.CompleteDatagram(second.Resolver, second.Payload);
    const auto firstReply = Forwarder.CompleteDatagram(first.Resolver, first.Payload);

    EXPECT_NE(first.Payload, second.Payload);
    EXPECT_TRUE(firstReply.has_value());
    EXPECT_TRUE(secondReply.has_value());
    EXPECT_EQ(firstReply.value().Client, Client);
    EXPECT_EQ(secondReply.value().Client, other);
    EXPECT_EQ(firstReply.value().Payload, Query);
    EXPECT_EQ(secondReply.value().Payload, Query);
}

TEST_F(Given_DnsForwarder, When_PolicyChangesDuringRequest_Then_OldResolverStillCompletes)
{
    const auto pending = Forwarder.Begin(Client, Query, Policy, Resolvers, {});
    ASSERT_EQ(pending.Status, DnsForwardStatus::Ready);
    Network.DnsDefaultResolvers({"198.51.100.53"});
    (void)Policy.Apply(Network);

    const auto reply = Forwarder.CompleteDatagram(pending.Resolver, pending.Payload);
    const auto next = Forwarder.Begin(Client, Query, Policy, Resolvers, {});

    EXPECT_TRUE(reply.has_value());
    EXPECT_EQ(reply.value().Client, Client);
    EXPECT_EQ(next.Resolver, Endpoint::Parse("198.51.100.53:53"));
}

TEST_F(Given_DnsForwarder, When_TunneledResolverResponds_Then_RequestReturnsToLocalClient)
{
    tailgate::types::netmap::PeerConfig peer;
    peer.Address("192.0.2.53");
    peer.AllowedPrefixes({tailgate::net::packet::Ipv4Prefix::Parse("192.0.2.53/32").value()});
    Network.Peers({peer});
    (void)Policy.Apply(Network);
    const auto pending = Forwarder.Begin(Client, Query, Policy, Resolvers, {});
    ASSERT_TRUE(pending.TunnelPacket.has_value());
    const auto response = Ipv4UdpDatagram::Build(pending.Resolver.Address().HostOrder(),
                                                 Ipv4Address::Parse("100.64.0.1").HostOrder(),
                                                 53,
                                                 Client.Port(),
                                                 pending.Payload);

    const auto reply = Forwarder.CompletePacket(response);

    EXPECT_TRUE(reply.has_value());
    EXPECT_EQ(reply.value().Client, Client);
    EXPECT_EQ(reply.value().Payload, Query);
}

TEST_F(Given_DnsForwarder, When_ResponseSourceIsWrong_Then_RequestRemainsPending)
{
    const auto pending = Forwarder.Begin(Client, Query, Policy, Resolvers, {});
    ASSERT_EQ(pending.Status, DnsForwardStatus::Ready);

    const auto wrongHost =
        Forwarder.CompleteDatagram(Endpoint::Parse("198.51.100.53:53"), pending.Payload);
    const auto wrongPort =
        Forwarder.CompleteDatagram(Endpoint::Parse("192.0.2.53:54"), pending.Payload);
    const auto reply = Forwarder.CompleteDatagram(pending.Resolver, pending.Payload);

    EXPECT_FALSE(wrongHost.has_value());
    EXPECT_FALSE(wrongPort.has_value());
    EXPECT_TRUE(reply.has_value());
}

TEST_F(Given_DnsForwarder, When_RequestExpires_Then_LateReplyIsIgnored)
{
    const auto pending = Forwarder.Begin(Client, Query, Policy, Resolvers, {});
    ASSERT_EQ(pending.Status, DnsForwardStatus::Ready);
    ASSERT_EQ(Forwarder.NextDeadline(), DnsForwarder::TimePoint(std::chrono::seconds(10)));

    Forwarder.Expire(DnsForwarder::TimePoint(std::chrono::seconds(10)));
    const auto reply = Forwarder.CompleteDatagram(pending.Resolver, pending.Payload);

    EXPECT_FALSE(reply.has_value());
    EXPECT_FALSE(Forwarder.NextDeadline().has_value());
}

TEST_F(Given_DnsForwarder, When_ResolverRequiresUnsupportedTransport_Then_FailureIsExplicit)
{
    Network.DnsDefaultResolvers({"https://dns.example.com/dns-query"});
    (void)Policy.Apply(Network);

    const auto result = Forwarder.Begin(Client, Query, Policy, Resolvers, {});

    EXPECT_EQ(result.Status, DnsForwardStatus::UnsupportedResolver);
    EXPECT_FALSE(Forwarder.NextDeadline().has_value());
}

TEST_F(Given_DnsForwarder, When_QueryIsTooShort_Then_NoRequestIsQueued)
{
    const std::vector<std::uint8_t> query{0};

    const auto result = Forwarder.Begin(Client, query, Policy, Resolvers, {});

    EXPECT_EQ(result.Status, DnsForwardStatus::InvalidQuery);
    EXPECT_FALSE(Forwarder.NextDeadline().has_value());
}

TEST_F(Given_DnsForwarder, When_RetransmissionGetsNewWireId_Then_OldReplyCannotCompleteNewRequest)
{
    const auto first = Forwarder.Begin(Client, Query, Policy, Resolvers, {});
    ASSERT_EQ(first.Status, DnsForwardStatus::Ready);
    Random = tailgate::tests::fakes::FakeRandom({0x56, 0x78});
    const auto second = Forwarder.Begin(Client, Query, Policy, Resolvers, {});
    ASSERT_EQ(second.Status, DnsForwardStatus::Ready);

    const auto oldReply = Forwarder.CompleteDatagram(first.Resolver, first.Payload);
    const auto reply = Forwarder.CompleteDatagram(second.Resolver, second.Payload);

    EXPECT_FALSE(oldReply.has_value());
    EXPECT_TRUE(reply.has_value());
    EXPECT_EQ(reply.value().Client, Client);
}

TEST_F(Given_DnsForwarder, When_PendingLimitIsReached_Then_AdditionalRequestIsRejected)
{
    constexpr std::size_t PendingLimit = 4096;
    auto query = Query;
    for (std::size_t index = 0; index < PendingLimit; ++index)
    {
        query[0] = static_cast<std::uint8_t>(index >> 8U);
        query[1] = static_cast<std::uint8_t>(index);
        const auto result = Forwarder.Begin(Client, query, Policy, Resolvers, {});
        ASSERT_EQ(result.Status, DnsForwardStatus::Ready);
    }
    query[0] = static_cast<std::uint8_t>(PendingLimit >> 8U);
    query[1] = static_cast<std::uint8_t>(PendingLimit);

    const auto result = Forwarder.Begin(Client, query, Policy, Resolvers, {});

    EXPECT_EQ(result.Status, DnsForwardStatus::Full);
}

TEST_F(Given_DnsForwarder, When_Reset_Then_DiscardsRequestsAndReleasesWireIds)
{
    const auto pending = Forwarder.Begin(Client, Query, Policy, Resolvers, {});
    ASSERT_EQ(pending.Status, DnsForwardStatus::Ready);

    Forwarder.Reset();
    const auto reply = Forwarder.CompleteDatagram(pending.Resolver, pending.Payload);
    const auto deadline = Forwarder.NextDeadline();
    const auto next = Forwarder.Begin(Client, Query, Policy, Resolvers, {});

    EXPECT_FALSE(reply);
    EXPECT_FALSE(deadline);
    EXPECT_EQ(next.Status, DnsForwardStatus::Ready);
    EXPECT_EQ(next.Payload, pending.Payload);
}
