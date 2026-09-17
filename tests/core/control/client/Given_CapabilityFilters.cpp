#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/control/client/NetworkMapParser.h>

namespace tailgate::tests
{

class Given_CapabilityFilters : public testing::Test
{
protected:
    Given_CapabilityFilters()
    {
        config.SelfAddress("100.64.0.1");
        config.SelfAddresses({"100.64.0.1", "2001:db8::1"});
        types::netmap::PeerConfig peer;
        peer.NodeId(42);
        peer.Address("100.64.0.2");
        peer.Addresses({"100.64.0.2", "2001:db8::2"});
        config.Peers({peer});
    }

    static constexpr const char* Grant = R"({"PacketFilter":[{"SrcIPs":["100.64.0.2/32"],
        "CapGrant":[{"Dsts":["100.64.0.1/32"],"CapMap":{"tailscale.com/cap/drive-sharer":[]}}]}]})";
    types::netmap::NetworkConfig config;
};

TEST_F(Given_CapabilityFilters, When_SourceAndDestinationMatch_Then_PeerReceivesCapability)
{
    const std::string update = Grant;

    const bool changed = control::client::NetworkMapParser::ApplyUpdate(config, update);

    EXPECT_TRUE(changed);
    EXPECT_EQ(config.Peers().front().Capabilities(),
              (std::vector<std::string>{"tailscale.com/cap/drive-sharer"}));
}

TEST_F(Given_CapabilityFilters, When_OnlyPeerNodeCapMapChanges_Then_NoPeerGrantIsInvented)
{
    const std::string update = R"({"PeersChangedPatch":[{"NodeID":42,
        "CapMap":{"tailscale.com/cap/drive-sharer":[]}}]})";

    (void)control::client::NetworkMapParser::ApplyUpdate(config, update);

    EXPECT_TRUE(config.Peers().front().Capabilities().empty());
}

TEST_F(Given_CapabilityFilters, When_GrantTargetsOtherNode_Then_PeerReceivesNothing)
{
    const std::string update = R"({"PacketFilter":[{"SrcIPs":["*"],"CapGrant":[{
        "Dsts":["100.64.0.99/32"],"Caps":["tailscale.com/cap/drive-sharer"]}]}]})";

    (void)control::client::NetworkMapParser::ApplyUpdate(config, update);

    EXPECT_TRUE(config.Peers().front().Capabilities().empty());
}

TEST_F(Given_CapabilityFilters, When_SourceAndDestinationFamiliesDiffer_Then_NoGrantApplies)
{
    const std::string update = R"({"PacketFilter":[{"SrcIPs":["100.64.0.2/32"],"CapGrant":[{
        "Dsts":["2001:db8::1/128"],"Caps":["tailscale.com/cap/drive-sharer"]}]}]})";

    (void)control::client::NetworkMapParser::ApplyUpdate(config, update);

    EXPECT_TRUE(config.Peers().front().Capabilities().empty());
}

TEST_F(Given_CapabilityFilters, When_Ipv6RangeMatches_Then_GrantApplies)
{
    const std::string update = R"({"PacketFilter":[{"SrcIPs":["2001:db8::2-2001:db8::3"],
        "CapGrant":[{"Dsts":["2001:db8::1/128"],"Caps":["tailscale.com/cap/drive-sharer"]}]}]})";

    (void)control::client::NetworkMapParser::ApplyUpdate(config, update);

    EXPECT_EQ(config.Peers().front().Capabilities(),
              (std::vector<std::string>{"tailscale.com/cap/drive-sharer"}));
}

TEST_F(Given_CapabilityFilters, When_ReplacementIsEmpty_Then_PreviousGrantIsRevoked)
{
    ASSERT_TRUE(control::client::NetworkMapParser::ApplyUpdate(config, Grant));
    ASSERT_FALSE(config.Peers().front().Capabilities().empty());

    const bool changed =
        control::client::NetworkMapParser::ApplyUpdate(config, R"({"PacketFilter":[]})");

    EXPECT_TRUE(changed);
    EXPECT_TRUE(config.Peers().front().Capabilities().empty());
}

TEST_F(Given_CapabilityFilters, When_UpdateOmitsFilters_Then_ExistingGrantRemains)
{
    ASSERT_TRUE(control::client::NetworkMapParser::ApplyUpdate(config, Grant));

    (void)control::client::NetworkMapParser::ApplyUpdate(config, R"({"OnlineChange":{"42":true}})");

    EXPECT_FALSE(config.Peers().front().Capabilities().empty());
}

TEST_F(Given_CapabilityFilters, When_NamedChunkIsDeleted_Then_OnlyItsGrantsAreRemoved)
{
    const std::string update = R"({"PacketFilters":{"base":[{"SrcIPs":["*"],"CapGrant":[{
        "Dsts":["100.64.0.1/32"],"Caps":["first"]}]}],"extra":[{"SrcIPs":["*"],
        "CapGrant":[{"Dsts":["100.64.0.1/32"],"Caps":["second"]}]}]}})";
    ASSERT_TRUE(control::client::NetworkMapParser::ApplyUpdate(config, update));

    (void)control::client::NetworkMapParser::ApplyUpdate(config,
                                                         R"({"PacketFilters":{"extra":null}})");

    EXPECT_EQ(config.Peers().front().Capabilities(), (std::vector<std::string>{"first"}));
}

TEST_F(Given_CapabilityFilters, When_ClearAllAccompaniesNewBase_Then_ClearRunsBeforeNamedAdds)
{
    ASSERT_TRUE(control::client::NetworkMapParser::ApplyUpdate(config, Grant));
    const std::string update = R"({"PacketFilter":[{"SrcIPs":["*"],"CapGrant":[{
        "Dsts":["100.64.0.1/32"],"Caps":["discarded"]}]}],
        "PacketFilters":{"*":null,"new":[{"SrcIPs":["*"],"CapGrant":[{
        "Dsts":["100.64.0.1/32"],"Caps":["retained"]}]}]}})";

    (void)control::client::NetworkMapParser::ApplyUpdate(config, update);

    EXPECT_EQ(config.Peers().front().Capabilities(), (std::vector<std::string>{"retained"}));
}

TEST_F(Given_CapabilityFilters, When_SelfNodeOmitsCapMap_Then_OldDriveAccessIsRevoked)
{
    config.Capabilities({"drive:access"});

    (void)control::client::NetworkMapParser::ApplyUpdate(config, R"({"Node":{"ID":1}})");

    EXPECT_FALSE(config.HasCapability("drive:access"));
}

TEST_F(Given_CapabilityFilters, When_SelfAddressChanges_Then_OldDestinationGrantStopsMatching)
{
    ASSERT_TRUE(control::client::NetworkMapParser::ApplyUpdate(config, Grant));
    ASSERT_FALSE(config.Peers().front().Capabilities().empty());

    (void)control::client::NetworkMapParser::ApplyUpdate(
        config, R"({"Node":{"Addresses":["100.64.0.3/32"]}})");

    EXPECT_EQ(config.SelfAddress(), "100.64.0.3");
    EXPECT_EQ(config.SelfAddresses(), (std::vector<std::string>{"100.64.0.3"}));
    EXPECT_TRUE(config.Peers().front().Capabilities().empty());
}

TEST_F(Given_CapabilityFilters, When_SelfAddressesAreCleared_Then_NoDestinationGrantMatches)
{
    ASSERT_TRUE(control::client::NetworkMapParser::ApplyUpdate(config, Grant));

    (void)control::client::NetworkMapParser::ApplyUpdate(config, R"({"Node":{"Addresses":[]}})");

    EXPECT_TRUE(config.SelfAddress().empty());
    EXPECT_TRUE(config.SelfAddresses().empty());
    EXPECT_TRUE(config.Peers().front().Capabilities().empty());
}

TEST_F(Given_CapabilityFilters, When_LaterNamedChunkIsInvalid_Then_FilterUpdateIsAtomic)
{
    ASSERT_TRUE(control::client::NetworkMapParser::ApplyUpdate(config, Grant));
    const std::string update = R"({"PacketFilters":{"base":[],"invalid":false}})";

    EXPECT_THROW((void)control::client::NetworkMapParser::ApplyUpdate(config, update),
                 std::exception);

    EXPECT_FALSE(config.Peers().front().Capabilities().empty());
    EXPECT_FALSE(config.CapabilityFilters().at("base").empty());
}

} // namespace tailgate::tests
