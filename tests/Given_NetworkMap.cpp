#include <gtest/gtest.h>

#include "tailgate/control/NetworkMap.h"

#include <string>

TEST(Tailgate, GivenNetworkMap_WhenPeerIsIpv6Only_ThenItRemainsVisibleInStatusData)
{
    const std::string json = R"({
        "Node":{"Addresses":["100.64.0.1/32"]},
        "Peers":[
            {
                "Name":"v4.example.",
                "Key":"nodekey:v4",
                "DiscoKey":"discokey:v4",
                "Addresses":["100.64.0.2/32"],
                "AllowedIPs":["100.100.100.100/32"],
                "DERP":"127.3.3.40:1"
            },
            {
                "Name":"v6.example.",
                "Key":"nodekey:v6",
                "Addresses":["fd7a:115c:a1e0::2/128"],
                "AllowedIPs":[],
                "DERP":"127.3.3.40:1"
            }
        ],
        "DNSConfig":{"Domains":[],"Routes":{"example.":[{"Addr":"100.100.100.100"}]}},
        "DERPMap":{
            "Regions":{
                "1":{
                    "RegionCode":"test",
                    "Nodes":[{"HostName":"derp.example","STUNOnly":false}]
                }
            }
        }
    })";

    const auto config = tailgate::control::ParseNetworkMap(json);

    ASSERT_TRUE(config.Peers.size() == 2);
    ASSERT_TRUE(config.Peers[1].Address == "fd7a:115c:a1e0::2");
    ASSERT_TRUE(config.Peers[0].DerpCode == "test");
    ASSERT_TRUE(config.Peers[0].DerpHost == "derp.example");

    const auto route = tailgate::control::FindRoute(config.Peers, 0x64646464U);

    ASSERT_TRUE(route.has_value());
    ASSERT_TRUE(*route == 0);
}

TEST(Tailgate, GivenMultipleExitNodes_WhenRoutingInternetTraffic_ThenSelectedNodeWins)
{
    tailgate::control::PeerConfig first;
    first.Name = "first.example.";
    first.Address = "100.64.0.2";
    first.Online = true;
    first.ExitNodeOption = true;
    first.AllowedPrefixes.push_back({0, 0});
    tailgate::control::PeerConfig second;
    second.Name = "second.example.";
    second.Address = "100.64.0.3";
    second.Online = true;
    second.ExitNodeOption = true;
    second.AllowedPrefixes.push_back({0, 0});
    const std::vector<tailgate::control::PeerConfig> peers{first, second};
    const auto selected = tailgate::control::FindExitNode(peers, "second");

    const auto route = tailgate::control::FindRoute(peers, 0x08080808U, selected);

    ASSERT_TRUE(selected.has_value());
    ASSERT_EQ(*selected, 1U);
    ASSERT_TRUE(route.has_value());
    EXPECT_EQ(*route, 1U);
}

TEST(Tailgate, GivenOfflineExitNode_WhenOnlineExitNodeIsRequired_ThenItIsRejected)
{
    tailgate::control::PeerConfig peer;
    peer.Name = "offline.example.";
    peer.Address = "100.64.0.2";
    peer.ExitNodeOption = true;
    peer.Online = false;
    const std::vector<tailgate::control::PeerConfig> peers{peer};

    const auto selected = tailgate::control::FindExitNode(peers, "offline", true);

    EXPECT_FALSE(selected.has_value());
}

TEST(Tailgate, GivenNoSelectedExitNode_WhenRoutingInternetTraffic_ThenDefaultRoutesAreIgnored)
{
    tailgate::control::PeerConfig exitNode;
    exitNode.ExitNodeOption = true;
    exitNode.AllowedPrefixes.push_back({0, 0});
    const std::vector<tailgate::control::PeerConfig> peers{exitNode};

    const auto route = tailgate::control::FindRoute(peers, 0x08080808U);

    EXPECT_FALSE(route.has_value());
}

TEST(Tailgate, GivenSelectedExitNodeAndSpecificRoute_WhenRouting_ThenSpecificRouteWins)
{
    tailgate::control::PeerConfig exitNode;
    exitNode.ExitNodeOption = true;
    exitNode.AllowedPrefixes.push_back({0, 0});
    tailgate::control::PeerConfig subnetRouter;
    subnetRouter.AllowedPrefixes.push_back({0x0a000000U, 8});
    const std::vector<tailgate::control::PeerConfig> peers{exitNode, subnetRouter};

    const auto route = tailgate::control::FindRoute(peers, 0x0a010203U, 0);

    ASSERT_TRUE(route.has_value());
    EXPECT_EQ(*route, 1U);
}

TEST(Tailgate, GivenSelectedExitNodeWithoutStoredDefaultPrefix_WhenRouting_ThenItIsTheFallback)
{
    tailgate::control::PeerConfig exitNode;
    exitNode.ExitNodeOption = true;
    const std::vector<tailgate::control::PeerConfig> peers{exitNode};

    const auto route = tailgate::control::FindRoute(peers, 0x08080808U, 0);

    ASSERT_TRUE(route.has_value());
    EXPECT_EQ(*route, 0U);
}

TEST(Tailgate, GivenNetworkConfigWithRegionCode_WhenFormattingDerp_ThenCodeIsReturned)
{
    tailgate::control::NetworkConfig config;
    tailgate::control::PeerConfig peer;
    peer.DerpRegion = 5;
    peer.DerpCode = "syd";
    config.Peers.push_back(peer);

    const std::string code = tailgate::control::DerpCode(config, 5);

    EXPECT_EQ(code, "syd");
    EXPECT_EQ(tailgate::control::DerpCode(config, 99), "derp-99");
}

TEST(Tailgate, GivenIncrementalPeerPatch_WhenApplyingNetworkMapUpdate_ThenPeerStateIsUpdated)
{
    tailgate::control::NetworkConfig config;
    tailgate::control::PeerConfig peer;
    peer.NodeId = 7;
    peer.Name = "patched.example.";
    peer.Address = "100.64.0.7";
    peer.DerpRegion = 1;
    config.DerpRegion = 1;
    config.Peers.push_back(peer);
    const std::string update = R"({
        "DERPMap":{
            "Regions":{
                "2":{
                    "RegionCode":"sfo",
                    "Nodes":[{"HostName":"derp2.example","STUNOnly":false}]
                }
            }
        },
        "PeersChangedPatch":[{
            "NodeID":7,
            "DERPRegion":2,
            "Online":true,
            "Endpoints":["10.0.0.7:41641","203.0.113.7:41641"]
        }]
    })";

    const bool changed = tailgate::control::ApplyNetworkMapUpdate(config, update);

    ASSERT_TRUE(changed);
    ASSERT_EQ(config.Peers.size(), 1U);
    EXPECT_TRUE(config.Peers[0].Online);
    EXPECT_EQ(config.Peers[0].DerpRegion, 2);
    EXPECT_EQ(config.Peers[0].DerpCode, "sfo");
    EXPECT_EQ(config.Peers[0].DerpHost, "derp2.example");
    ASSERT_EQ(config.Peers[0].Endpoints.size(), 2U);
    EXPECT_EQ(config.Peers[0].Endpoints[0], "203.0.113.7:41641");
}

TEST(Tailgate, GivenIncrementalPeerRemoval_WhenApplyingNetworkMapUpdate_ThenPeerIsRemoved)
{
    tailgate::control::NetworkConfig config;
    tailgate::control::PeerConfig removed;
    removed.NodeId = 7;
    tailgate::control::PeerConfig kept;
    kept.NodeId = 8;
    config.Peers = {removed, kept};
    const std::string update = R"({"PeersRemoved":[7]})";

    const bool changed = tailgate::control::ApplyNetworkMapUpdate(config, update);

    ASSERT_TRUE(changed);
    ASSERT_EQ(config.Peers.size(), 1U);
    EXPECT_EQ(config.Peers[0].NodeId, 8U);
}

TEST(Tailgate, GivenIncrementalPeerChangeWithoutDerpMap_WhenApplying_ThenDerpMetadataIsPreserved)
{
    tailgate::control::NetworkConfig config;
    tailgate::control::PeerConfig existing;
    existing.NodeId = 7;
    existing.DerpRegion = 1;
    existing.DerpCode = "nyc";
    existing.DerpHost = "derp1.example";
    config.Peers.push_back(existing);
    const std::string update = R"({
        "PeersChanged":[{
            "ID":7,
            "Name":"changed.example.",
            "Key":"nodekey:abc",
            "Addresses":["100.64.0.7/32"],
            "AllowedIPs":["100.64.0.7/32"],
            "DERP":"127.3.3.40:1"
        }]
    })";

    const bool changed = tailgate::control::ApplyNetworkMapUpdate(config, update);

    ASSERT_TRUE(changed);
    ASSERT_EQ(config.Peers.size(), 1U);
    EXPECT_EQ(config.Peers[0].Name, "changed.example.");
    EXPECT_EQ(config.Peers[0].DerpCode, "nyc");
    EXPECT_EQ(config.Peers[0].DerpHost, "derp1.example");
}

TEST(Tailgate, GivenIncrementalOnlineChange_WhenApplyingNetworkMapUpdate_ThenPeerOnlineChanges)
{
    tailgate::control::NetworkConfig config;
    tailgate::control::PeerConfig peer;
    peer.NodeId = 7;
    peer.Online = false;
    config.Peers.push_back(peer);
    const std::string update = R"({"OnlineChange":{"7":true}})";

    const bool changed = tailgate::control::ApplyNetworkMapUpdate(config, update);

    ASSERT_TRUE(changed);
    ASSERT_EQ(config.Peers.size(), 1U);
    EXPECT_TRUE(config.Peers[0].Online);
}

TEST(Tailgate, GivenIncrementalDiscoKeyPatch_WhenApplyingNetworkMapUpdate_ThenDiscoKeyChanges)
{
    tailgate::control::NetworkConfig config;
    tailgate::control::PeerConfig peer;
    peer.NodeId = 7;
    peer.DiscoKey = "discokey:old";
    config.Peers.push_back(peer);
    const std::string update = R"({
        "PeersChangedPatch":[{
            "NodeID":7,
            "DiscoKey":"discokey:new"
        }]
    })";

    const bool changed = tailgate::control::ApplyNetworkMapUpdate(config, update);

    ASSERT_TRUE(changed);
    ASSERT_EQ(config.Peers.size(), 1U);
    EXPECT_EQ(config.Peers[0].DiscoKey, "discokey:new");
}

TEST(Tailgate, GivenIncrementalObjectDiscoKeyPatch_WhenApplyingNetworkMapUpdate_ThenDiscoKeyChanges)
{
    tailgate::control::NetworkConfig config;
    tailgate::control::PeerConfig peer;
    peer.NodeId = 7;
    peer.DiscoKey = "discokey:old";
    config.Peers.push_back(peer);
    const std::string update = R"({
        "PeersChangedPatch":[{
            "NodeID":7,
            "DiscoKey":{
                "String":"discokey:new"
            }
        }]
    })";

    const bool changed = tailgate::control::ApplyNetworkMapUpdate(config, update);

    ASSERT_TRUE(changed);
    ASSERT_EQ(config.Peers.size(), 1U);
    EXPECT_EQ(config.Peers[0].DiscoKey, "discokey:new");
}

TEST(Tailgate, GivenIncrementalPeerSeenFalse_WhenApplyingNetworkMapUpdate_ThenPeerIsOffline)
{
    tailgate::control::NetworkConfig config;
    tailgate::control::PeerConfig peer;
    peer.NodeId = 7;
    peer.Online = true;
    config.Peers.push_back(peer);
    const std::string update = R"({"PeerSeenChange":{"7":false}})";

    const bool changed = tailgate::control::ApplyNetworkMapUpdate(config, update);

    ASSERT_TRUE(changed);
    ASSERT_EQ(config.Peers.size(), 1U);
    EXPECT_FALSE(config.Peers[0].Online);
}

TEST(Tailgate, GivenIncrementalDnsConfig_WhenApplyingNetworkMapUpdate_ThenDnsRoutesAreReplaced)
{
    tailgate::control::NetworkConfig config;
    config.DnsDomains = {"old.nt"};
    config.DnsRoutes.push_back({"old.nt.", {"100.100.100.100"}});
    const std::string update = R"({
        "DNSConfig":{"Domains":["new.nt"],"Routes":{"new.nt.":[{"Addr":"100.100.100.101"}]}}
    })";

    const bool changed = tailgate::control::ApplyNetworkMapUpdate(config, update);

    ASSERT_TRUE(changed);
    ASSERT_EQ(config.DnsDomains.size(), 1U);
    EXPECT_EQ(config.DnsDomains[0], "new.nt");
    ASSERT_EQ(config.DnsRoutes.size(), 1U);
    EXPECT_EQ(config.DnsRoutes[0].Suffix, "new.nt.");
    ASSERT_EQ(config.DnsRoutes[0].Resolvers.size(), 1U);
    EXPECT_EQ(config.DnsRoutes[0].Resolvers[0], "100.100.100.101");
}
