#include <string>

#include <gtest/gtest.h>

#include <tailgate/control/NetworkMap.h>

TEST(Given_NetworkMap, When_PeerIsIpv6Only_Then_ItRemainsVisibleInStatusData)
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
                    "Nodes":[
                        {"HostName":"derp.example","STUNOnly":false,"STUNPort":-1},
                        {"HostName":"stun.example","IPv4":"192.0.2.5","STUNOnly":true,
                         "STUNPort":3479}
                    ]
                }
            }
        }
    })";

    const auto config = tailgate::control::ParseNetworkMap(json);

    ASSERT_TRUE(config.Peers.size() == 2);
    ASSERT_TRUE(config.Peers[1].Address == "fd7a:115c:a1e0::2");
    ASSERT_TRUE(config.Peers[0].DerpCode == "test");
    ASSERT_TRUE(config.Peers[0].DerpHost == "derp.example");
    EXPECT_EQ(config.StunHost, "192.0.2.5");
    EXPECT_EQ(config.StunPort, 3479);

    const auto route = tailgate::control::FindRoute(config.Peers, 0x64646464U);

    ASSERT_TRUE(route.has_value());
    ASSERT_TRUE(*route == 0);
}

TEST(Given_NetworkMapPeerWithIpv4AndIpv6, When_Parsed_Then_AllAddressesAreRetained)
{
    const std::string json = R"({
        "Node":{"Addresses":["100.64.0.1/32"]},
        "Peers":[
            {
                "Name":"dual.example.",
                "Key":"nodekey:dual",
                "Addresses":["100.64.0.2/32","fd7a:115c:a1e0::2/128"],
                "AllowedIPs":["100.100.100.100/32"],
                "Hostinfo":{
                    "OS":"linux",
                    "IPNVersion":"1.98.8",
                    "WireIngress":true,
                    "IngressEnabled":true,
                    "Services":[
                        {"Proto":"peerapi4","Port":41112},
                        {"Proto":"peerapi6","Port":41113}
                    ]
                },
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

    EXPECT_TRUE(config.Peers.size() == 1);
    EXPECT_TRUE(config.Peers[0].Address == "100.64.0.2");
    EXPECT_TRUE(config.Peers[0].Addresses.size() == 2);
    EXPECT_TRUE(config.Peers[0].Addresses[1] == "fd7a:115c:a1e0::2");
    EXPECT_TRUE(config.Peers[0].ClientVersion == "1.98.8");
    EXPECT_TRUE(config.Peers[0].WireIngress);
    EXPECT_TRUE(config.Peers[0].IngressEnabled);
    EXPECT_TRUE(config.Peers[0].PeerApi4Port == 41112);
    EXPECT_TRUE(config.Peers[0].PeerApi6Port == 41113);
}

TEST(Given_MultipleExitNodes, When_RoutingInternetTraffic_Then_SelectedNodeWins)
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

TEST(Given_OfflineExitNode, When_OnlineExitNodeIsRequired_Then_ItIsRejected)
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

TEST(Given_ConfiguredExitNode, When_AvailabilityChanges_Then_SelectionTracksNetworkMap)
{
    tailgate::control::PeerConfig offline;
    offline.Name = "exit.example.";
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

    const auto route = tailgate::control::FindRoute(peers, 0x08080808U);

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

    ASSERT_TRUE(route.has_value());
    EXPECT_EQ(*route, 1U);
}

TEST(Given_SelectedExitNodeWithoutStoredDefaultPrefix, When_Routing_Then_ItIsTheFallback)
{
    tailgate::control::PeerConfig exitNode;
    exitNode.ExitNodeOption = true;
    const std::vector<tailgate::control::PeerConfig> peers{exitNode};

    const auto route = tailgate::control::FindRoute(peers, 0x08080808U, 0);

    ASSERT_TRUE(route.has_value());
    EXPECT_EQ(*route, 0U);
}

TEST(Given_NetworkConfigWithRegionCode, When_FormattingDerp_Then_CodeIsReturned)
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

TEST(Given_TaggedNodeUser, When_ParsingNetworkMap_Then_HumanAccountIsPreferred)
{
    const std::string json = R"({
        "Domain":"example.ts.net",
        "Node":{
            "Name":"self.example.ts.net.",
            "Addresses":["100.64.0.1/32"],
            "User":7
        },
        "UserProfiles":[
            {"ID":7,"LoginName":"tagged-devices","DisplayName":"Tagged Devices"},
            {"ID":42,"LoginName":"owner@example.com","DisplayName":"Example Owner",
             "ProfilePicURL":"https://cdn.example/owner.png"}
        ],
        "Peers":[
            {
                "Name":"dns.example.",
                "Key":"nodekey:dns",
                "User":42,
                "Addresses":["100.64.0.2/32"],
                "AllowedIPs":["100.100.100.100/32"],
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
    EXPECT_EQ(1U, config.Peers.size());

    EXPECT_EQ(config.AccountName, "owner@example.com");
    EXPECT_EQ(config.AccountDisplayName, "Example Owner");
    EXPECT_EQ(config.AccountProfilePicUrl, "https://cdn.example/owner.png");
    EXPECT_EQ(config.Peers.front().Owner, "Example Owner");
}

TEST(Given_NetworkMapDomain, When_ParsingAndUpdating_Then_DomainIsStored)
{
    const std::string json = R"({
        "Domain":"example.ts.net",
        "Node":{
            "Name":"self.example.ts.net.",
            "Addresses":["100.64.0.1/32"],
            "User":42,
            "CapMap":{"tailnet-display-name":["Example Lab"]}
        },
        "UserProfiles":[{"ID":42,"LoginName":"owner@example.com","DisplayName":"Example Owner"}],
        "Peers":[
            {
                "Name":"dns.example.",
                "Key":"nodekey:dns",
                "Addresses":["100.64.0.2/32"],
                "AllowedIPs":["100.100.100.100/32"],
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

    auto config = tailgate::control::ParseNetworkMap(json);

    EXPECT_EQ(config.Domain, "example.ts.net");
    EXPECT_EQ(config.SelfName, "self.example.ts.net");
    EXPECT_EQ(config.MagicDnsDomain, "example.ts.net");
    EXPECT_EQ(config.TailnetDisplayName, "Example Lab");
    EXPECT_EQ(config.AccountName, "owner@example.com");
    EXPECT_EQ(config.AccountDisplayName, "Example Owner");

    const bool changed = tailgate::control::ApplyNetworkMapUpdate(config,
                                                                  R"({
                "Domain":"renamed.ts.net",
                "Node":{
                    "Name":"self.renamed.ts.net.",
                    "User":42,
                    "CapMap":{"tailnet-display-name":["Renamed Lab"]}
                },
                "UserProfiles":[{"ID":42,"LoginName":"new-owner@example.com","DisplayName":"New Owner"}]
            })");

    ASSERT_TRUE(changed);
    EXPECT_EQ(config.Domain, "renamed.ts.net");
    EXPECT_EQ(config.SelfName, "self.renamed.ts.net");
    EXPECT_EQ(config.MagicDnsDomain, "renamed.ts.net");
    EXPECT_EQ(config.TailnetDisplayName, "Renamed Lab");
    EXPECT_EQ(config.AccountName, "new-owner@example.com");
    EXPECT_EQ(config.AccountDisplayName, "New Owner");
}

TEST(Given_NetworkMapCapabilities, When_Parsing_Then_FunnelPortsAreDetected)
{
    const std::string json = R"({
        "Domain":"example.ts.net",
        "Node":{
            "Name":"self.example.ts.net.",
            "Addresses":["100.64.0.1/32"],
            "CapMap":{
                "https":null,
                "funnel":null,
                "https://tailscale.com/cap/funnel-ports?ports=443,10000-10010":null
            }
        },
        "Peers":[
            {
                "Name":"dns.example.",
                "Key":"nodekey:dns",
                "Addresses":["100.64.0.2/32"],
                "AllowedIPs":["100.100.100.100/32"],
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

    EXPECT_TRUE(tailgate::control::HasCapability(config, "https"));
    EXPECT_TRUE(tailgate::control::HasCapability(config, "funnel"));
    EXPECT_TRUE(tailgate::control::AllowsFunnelPort(config, 443));
    EXPECT_TRUE(tailgate::control::AllowsFunnelPort(config, 10000));
    EXPECT_TRUE(tailgate::control::AllowsFunnelPort(config, 10010));
    EXPECT_FALSE(tailgate::control::AllowsFunnelPort(config, 10011));
}

TEST(Given_IncrementalPeerPatch, When_ApplyingNetworkMapUpdate_Then_PeerStateIsUpdated)
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

TEST(Given_IncrementalPeerRemoval, When_ApplyingNetworkMapUpdate_Then_PeerIsRemoved)
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
    EXPECT_EQ(config.RemovedPeerNodeIds.size(), 1U);
    EXPECT_EQ(config.RemovedPeerNodeIds[0], 7U);
}

TEST(Given_IncrementalPeerChangeWithoutDerpMap, When_Applying_Then_DerpMetadataIsPreserved)
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

TEST(Given_NewTaggedPeerWithoutUserProfiles, When_ApplyingUpdate_Then_CachedOwnerIsUsed)
{
    tailgate::control::NetworkConfig config;
    config.UserProfiles.push_back(tailgate::control::UserProfile{.Id = 7,
                                                                 .LoginName = "tagged-devices",
                                                                 .DisplayName = "Tagged Devices",
                                                                 .ProfilePicUrl = {}});
    const std::string update = R"({
        "PeersChanged":[{
            "ID":101,
            "User":7,
            "Name":"jail-101.example.",
            "Key":"nodekey:abc",
            "Addresses":["100.64.0.101/32"],
            "AllowedIPs":["100.64.0.101/32"],
            "DERP":"127.3.3.40:1"
        }]
    })";

    const bool changed = tailgate::control::ApplyNetworkMapUpdate(config, update);

    ASSERT_TRUE(changed);
    ASSERT_EQ(config.Peers.size(), 1U);
    EXPECT_EQ(config.Peers.front().OwnerId, 7U);
    EXPECT_EQ(config.Peers.front().Owner, "Tagged Devices");
}

TEST(Given_NewExitNodePeer, When_ApplyingUpdate_Then_ExitNodeOptionIsAvailable)
{
    tailgate::control::NetworkConfig config;
    const std::string update = R"({
        "PeersChanged":[{
            "ID":102,
            "Name":"exit.example.",
            "Key":"nodekey:def",
            "Addresses":["100.64.0.102/32"],
            "AllowedIPs":["100.64.0.102/32","0.0.0.0/0"],
            "DERP":"127.3.3.40:1",
            "Online":true
        }]
    })";

    const bool changed = tailgate::control::ApplyNetworkMapUpdate(config, update);

    ASSERT_TRUE(changed);
    ASSERT_EQ(config.Peers.size(), 1U);
    EXPECT_TRUE(config.Peers.front().ExitNodeOption);
    EXPECT_TRUE(config.Peers.front().Online);
}

TEST(Given_IncrementalOnlineChange, When_ApplyingNetworkMapUpdate_Then_PeerOnlineChanges)
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

TEST(Given_MachineApprovalUpdate, When_ApplyingNetworkMapUpdate_Then_SelfIsAuthorized)
{
    tailgate::control::NetworkConfig config;
    config.SelfMachineAuthorized = false;
    const std::string update = R"({"Node":{"MachineAuthorized":true}})";

    const bool changed = tailgate::control::ApplyNetworkMapUpdate(config, update);

    EXPECT_TRUE(changed);
    EXPECT_TRUE(config.SelfMachineAuthorized);
}

TEST(Given_IncrementalDiscoKeyPatch, When_ApplyingNetworkMapUpdate_Then_DiscoKeyChanges)
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

TEST(Given_IncrementalObjectDiscoKeyPatch, When_ApplyingNetworkMapUpdate_Then_DiscoKeyChanges)
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

TEST(Given_IncrementalPeerSeenFalse, When_ApplyingNetworkMapUpdate_Then_OnlyLastSeenClears)
{
    tailgate::control::NetworkConfig config;
    tailgate::control::PeerConfig peer;
    peer.NodeId = 7;
    peer.Online = true;
    peer.LastSeen = "2026-07-20T00:00:00Z";
    config.Peers.push_back(peer);
    const std::string update = R"({"PeerSeenChange":{"7":false}})";

    const bool changed = tailgate::control::ApplyNetworkMapUpdate(config, update);

    ASSERT_TRUE(changed);
    ASSERT_EQ(config.Peers.size(), 1U);
    EXPECT_TRUE(config.Peers[0].LastSeen.empty());
    EXPECT_TRUE(config.Peers[0].Online);
}

TEST(Given_IncrementalPeerSeenTrue, When_ApplyingNetworkMapUpdate_Then_OnlyLastSeenUpdates)
{
    tailgate::control::NetworkConfig config;
    tailgate::control::PeerConfig peer;
    peer.NodeId = 7;
    peer.Online = false;
    config.Peers.push_back(peer);
    const std::string update = R"({"PeerSeenChange":{"7":true}})";

    const bool changed = tailgate::control::ApplyNetworkMapUpdate(config, update);

    ASSERT_TRUE(changed);
    ASSERT_EQ(config.Peers.size(), 1U);
    EXPECT_FALSE(config.Peers[0].LastSeen.empty());
    EXPECT_FALSE(config.Peers[0].Online);
}

TEST(Given_IncrementalLastSeenPatch, When_ApplyingNetworkMapUpdate_Then_TimestampsChange)
{
    tailgate::control::NetworkConfig config;
    tailgate::control::PeerConfig peer;
    peer.NodeId = 7;
    config.Peers.push_back(peer);
    const std::string update = R"({
        "PeersChangedPatch":[{
            "NodeID":7,
            "LastSeen":"2026-07-20T01:02:03Z",
            "KeyExpiry":"2026-12-31T00:00:00Z"
        }]
    })";

    const bool changed = tailgate::control::ApplyNetworkMapUpdate(config, update);

    ASSERT_TRUE(changed);
    ASSERT_EQ(config.Peers.size(), 1U);
    EXPECT_EQ(config.Peers[0].LastSeen, "2026-07-20T01:02:03Z");
    EXPECT_EQ(config.Peers[0].KeyExpiry, "2026-12-31T00:00:00Z");
}

TEST(Given_IncrementalDnsConfig, When_ApplyingNetworkMapUpdate_Then_DnsRoutesAreReplaced)
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
