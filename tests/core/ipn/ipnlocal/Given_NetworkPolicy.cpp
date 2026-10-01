#include <algorithm>

#include <gtest/gtest.h>

#include <tailgate/ipn/ipnlocal/NetworkPolicy.h>

TEST(Given_NetworkPolicy, When_ExitNodeDisappears_Then_DefaultRoutesAreWithdrawn)
{
    tailgate::types::netmap::PeerConfig peer;
    peer.Name("exit.example.ts.net");
    peer.Address("100.64.0.2");
    peer.Online(true);
    peer.ExitNodeOption(true);
    peer.AllowedPrefixes({tailgate::net::packet::Ipv4Prefix::Parse("0.0.0.0/0").value()});
    tailgate::types::netmap::NetworkConfig network;
    network.SelfAddress("100.64.0.1");
    network.Peers({peer});
    tailgate::ipn::ipnlocal::NetworkPolicy policy("exit.example.ts.net");
    (void)policy.Apply(network);
    ASSERT_TRUE(policy.ExitPeer().has_value());
    const auto original = policy.Routes();
    network.Peers({});

    const auto changed = policy.Apply(network);

    EXPECT_FALSE(policy.ExitPeer().has_value());
    EXPECT_EQ(changed.PreviousRoutes, original);
    EXPECT_NE(policy.Routes(), original);
}

TEST(Given_NetworkPolicy, When_DnsDomainsChange_Then_HostResolverNeedsUpdating)
{
    tailgate::types::netmap::NetworkConfig network;
    network.SelfAddress("100.64.0.1");
    network.DnsResolver("100.100.100.100");
    tailgate::ipn::ipnlocal::NetworkPolicy policy("");
    (void)policy.Apply(network);
    network.DnsDomains({"example.ts.net"});

    const auto changed = policy.Apply(network);

    EXPECT_TRUE(changed.DnsChanged);
    EXPECT_EQ(policy.Network().DnsDomains(), network.DnsDomains());
}

TEST(Given_NetworkPolicy, When_MapIsUnchanged_Then_HostPolicyIsUnchanged)
{
    tailgate::types::netmap::NetworkConfig network;
    network.SelfAddress("100.64.0.1");
    network.DnsResolver("100.100.100.100");
    tailgate::ipn::ipnlocal::NetworkPolicy policy("");
    (void)policy.Apply(network);

    const auto changed = policy.Apply(network);

    EXPECT_FALSE(changed.DnsChanged);
    EXPECT_EQ(changed.PreviousRoutes, policy.Routes());
}
