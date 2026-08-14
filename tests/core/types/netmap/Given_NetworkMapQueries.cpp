#include <gtest/gtest.h>

#include <tailgate/control/NetworkMap.h>

TEST(Given_MultipleExitNodes, When_RoutingInternetTraffic_Then_SelectedNodeWins)
{
    tailgate::control::PeerConfig first;
    first.Name = "first.example.com.";
    first.Address = "100.64.0.2";
    first.Online = true;
    first.ExitNodeOption = true;
    first.AllowedPrefixes.push_back({0, 0});
    tailgate::control::PeerConfig second;
    second.Name = "second.example.com.";
    second.Address = "100.64.0.3";
    second.Online = true;
    second.ExitNodeOption = true;
    second.AllowedPrefixes.push_back({0, 0});
    const std::vector<tailgate::control::PeerConfig> peers{first, second};

    const auto selected = tailgate::control::FindExitNode(peers, "second");
    const auto route = tailgate::control::FindRoute(peers, 0xcb00710aU, selected);
    const bool selectedExpectedPeer = selected.has_value() && *selected == 1U;
    const bool routedThroughExpectedPeer = route.has_value() && *route == 1U;

    EXPECT_TRUE(selectedExpectedPeer);
    EXPECT_TRUE(routedThroughExpectedPeer);
}

TEST(Given_OfflineExitNode, When_OnlineExitNodeIsRequired_Then_ItIsRejected)
{
    tailgate::control::PeerConfig peer;
    peer.Name = "offline.example.com.";
    peer.Address = "100.64.0.2";
    peer.ExitNodeOption = true;
    peer.Online = false;
    const std::vector<tailgate::control::PeerConfig> peers{peer};

    const auto selected = tailgate::control::FindExitNode(peers, "offline", true);

    EXPECT_FALSE(selected.has_value());
}

TEST(Given_ConfiguredExitNode, When_AvailabilityChanges_Then_SelectionTracksNetworkMap)
{
    tailgate::control::PeerConfig offline;
    offline.Name = "exit.example.com.";
    offline.Address = "100.64.0.2";
    offline.ExitNodeOption = true;
    offline.Online = false;
    tailgate::control::PeerConfig online = offline;
    online.Online = true;

    const auto unavailable = tailgate::control::FindExitNode({offline}, "exit", true);
    const auto available = tailgate::control::FindExitNode({online}, "exit", true);

    EXPECT_FALSE(unavailable.has_value());
    EXPECT_EQ(available, 0U);
}

TEST(Given_NoSelectedExitNode, When_RoutingInternetTraffic_Then_DefaultRoutesAreIgnored)
{
    tailgate::control::PeerConfig exitNode;
    exitNode.ExitNodeOption = true;
    exitNode.AllowedPrefixes.push_back({0, 0});
    const std::vector<tailgate::control::PeerConfig> peers{exitNode};

    const auto route = tailgate::control::FindRoute(peers, 0xcb00710aU);

    EXPECT_FALSE(route.has_value());
}

TEST(Given_SelectedExitNodeAndSpecificRoute, When_Routing_Then_SpecificRouteWins)
{
    tailgate::control::PeerConfig exitNode;
    exitNode.ExitNodeOption = true;
    exitNode.AllowedPrefixes.push_back({0, 0});
    tailgate::control::PeerConfig subnetRouter;
    subnetRouter.AllowedPrefixes.push_back({0x0a000000U, 8});
    const std::vector<tailgate::control::PeerConfig> peers{exitNode, subnetRouter};

    const auto route = tailgate::control::FindRoute(peers, 0x0a010203U, 0);

    EXPECT_EQ(route, 1U);
}

TEST(Given_SelectedExitNodeWithoutStoredDefaultPrefix, When_Routing_Then_ItIsTheFallback)
{
    tailgate::control::PeerConfig exitNode;
    exitNode.ExitNodeOption = true;
    const std::vector<tailgate::control::PeerConfig> peers{exitNode};

    const auto route = tailgate::control::FindRoute(peers, 0xcb00710aU, 0);

    EXPECT_EQ(route, 0U);
}

TEST(Given_NetworkConfigWithRegionCode, When_FormattingDerp_Then_CodeIsReturned)
{
    tailgate::control::NetworkConfig config;
    tailgate::control::PeerConfig peer;
    peer.DerpRegion = 5;
    peer.DerpCode = "syd";
    config.Peers.push_back(peer);

    const std::string code = tailgate::control::DerpCode(config, 5);
    const std::string unknownCode = tailgate::control::DerpCode(config, 99);

    EXPECT_EQ(code, "syd");
    EXPECT_EQ(unknownCode, "derp-99");
}
