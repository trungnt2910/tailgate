#include <gtest/gtest.h>

#include <tailgate/net/Ipv4Address.h>
#include <tailgate/types/netmap/NetworkMap.h>

TEST(Given_NetworkConfig, When_MultipleExitNodesAndRoutingInternetTraffic_Then_SelectedNodeWins)
{
    tailgate::types::netmap::PeerConfig first;
    first.Name("first.example.com.");
    first.Address("100.64.0.2");
    first.Online(true);
    first.ExitNodeOption(true);
    first.AllowedPrefixes({{0, 0}});
    tailgate::types::netmap::PeerConfig second;
    second.Name("second.example.com.");
    second.Address("100.64.0.3");
    second.Online(true);
    second.ExitNodeOption(true);
    second.AllowedPrefixes({{0, 0}});
    tailgate::types::netmap::NetworkConfig network;
    network.Peers({first, second});

    const auto selected = network.FindExitNode("second");
    const auto route = network.FindRoute(
        tailgate::net::Ipv4Address::FromOctets(203, 0, 113, 10).HostOrder(), selected);
    const bool selectedExpectedPeer = selected.has_value() && *selected == 1U;
    const bool routedThroughExpectedPeer = route.has_value() && *route == 1U;

    EXPECT_TRUE(selectedExpectedPeer);
    EXPECT_TRUE(routedThroughExpectedPeer);
}

TEST(Given_NetworkConfig, When_OfflineExitNodeAndOnlineExitNodeIsRequired_Then_ItIsRejected)
{
    tailgate::types::netmap::PeerConfig peer;
    peer.Name("offline.example.com.");
    peer.Address("100.64.0.2");
    peer.ExitNodeOption(true);
    peer.Online(false);
    tailgate::types::netmap::NetworkConfig network;
    network.Peers({peer});

    const auto selected = network.FindExitNode("offline", true);

    EXPECT_FALSE(selected.has_value());
}

TEST(Given_NetworkConfig,
     When_ConfiguredExitNodeAndAvailabilityChanges_Then_SelectionTracksNetworkMap)
{
    tailgate::types::netmap::PeerConfig offline;
    offline.Name("exit.example.com.");
    offline.Address("100.64.0.2");
    offline.ExitNodeOption(true);
    offline.Online(false);
    tailgate::types::netmap::PeerConfig online = offline;
    online.Online(true);

    tailgate::types::netmap::NetworkConfig unavailableNetwork;
    unavailableNetwork.Peers({offline});
    tailgate::types::netmap::NetworkConfig availableNetwork;
    availableNetwork.Peers({online});

    const auto unavailable = unavailableNetwork.FindExitNode("exit", true);
    const auto available = availableNetwork.FindExitNode("exit", true);

    EXPECT_FALSE(unavailable.has_value());
    EXPECT_EQ(available, 0U);
}

TEST(Given_NetworkConfig,
     When_NoSelectedExitNodeAndRoutingInternetTraffic_Then_DefaultRoutesAreIgnored)
{
    tailgate::types::netmap::PeerConfig exitNode;
    exitNode.ExitNodeOption(true);
    exitNode.AllowedPrefixes({{0, 0}});
    tailgate::types::netmap::NetworkConfig network;
    network.Peers({exitNode});

    const auto route =
        network.FindRoute(tailgate::net::Ipv4Address::FromOctets(203, 0, 113, 10).HostOrder());

    EXPECT_FALSE(route.has_value());
}

TEST(Given_NetworkConfig, When_SelectedExitNodeAndSpecificRouteAndRouting_Then_SpecificRouteWins)
{
    tailgate::types::netmap::PeerConfig exitNode;
    exitNode.ExitNodeOption(true);
    exitNode.AllowedPrefixes({{0, 0}});
    tailgate::types::netmap::PeerConfig subnetRouter;
    subnetRouter.AllowedPrefixes({tailgate::net::packet::Ipv4Prefix(
        tailgate::net::Ipv4Address::FromOctets(10, 0, 0, 0).HostOrder(), 8)});
    tailgate::types::netmap::NetworkConfig network;
    network.Peers({exitNode, subnetRouter});

    const auto route =
        network.FindRoute(tailgate::net::Ipv4Address::FromOctets(10, 1, 2, 3).HostOrder(), 0);

    EXPECT_EQ(route, 1U);
}

TEST(Given_NetworkConfig,
     When_SelectedExitNodeWithoutStoredDefaultPrefixAndRouting_Then_ItIsTheFallback)
{
    tailgate::types::netmap::PeerConfig exitNode;
    exitNode.ExitNodeOption(true);
    tailgate::types::netmap::NetworkConfig network;
    network.Peers({exitNode});

    const auto route =
        network.FindRoute(tailgate::net::Ipv4Address::FromOctets(203, 0, 113, 10).HostOrder(), 0);

    EXPECT_EQ(route, 0U);
}

TEST(Given_NetworkConfig, When_NetworkConfigWithRegionCodeAndFormattingDerp_Then_CodeIsReturned)
{
    tailgate::types::netmap::NetworkConfig config;
    tailgate::types::netmap::PeerConfig peer;
    peer.DerpRegion(5);
    peer.DerpCode("syd");
    config.Peers({peer});

    const std::string code = config.DerpCodeForRegion(5);
    const std::string unknownCode = config.DerpCodeForRegion(99);

    EXPECT_EQ(code, "syd");
    EXPECT_EQ(unknownCode, "derp-99");
}

TEST(Given_NetworkConfig, When_PeerHasMultipleAddresses_Then_AnyAddressFindsThePeer)
{
    tailgate::types::netmap::PeerConfig peer;
    peer.Name("peer.example.ts.net.");
    peer.Address("100.64.0.2");
    peer.Addresses({"100.64.0.2", "fd7a:115c:a1e0::2"});
    tailgate::types::netmap::NetworkConfig network;
    network.Peers({peer});

    const auto byShortName = network.FindPeer("peer");
    const auto byIpv6 = network.FindPeer("fd7a:115c:a1e0::2");

    EXPECT_EQ(byShortName, 0U);
    EXPECT_EQ(byIpv6, 0U);
    EXPECT_EQ(peer.DisplayName(), "peer");
}
