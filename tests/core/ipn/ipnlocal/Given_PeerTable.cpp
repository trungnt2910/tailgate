#include <gtest/gtest.h>

#include <tailgate/ipn/ipnlocal/PeerTable.h>

namespace
{

tailgate::types::netmap::PeerConfig Peer()
{
    tailgate::types::netmap::PeerConfig peer;
    peer.NodeId(1);
    peer.Name("peer.example.ts.net");
    peer.Address("100.64.0.2");
    peer.Key("nodekey:" + std::string(64, '1'));
    peer.DiscoKey("discokey:" + std::string(64, '2'));
    peer.AllowedPrefixes({tailgate::net::packet::Ipv4Prefix::Parse("100.64.0.2/32").value()});
    peer.Online(true);
    return peer;
}

} // namespace

TEST(Given_PeerTable, When_PeerIsUpdated_Then_AccountingAndEntryRemainStable)
{
    tailgate::ipn::ipnlocal::PeerTable table;
    auto peer = Peer();
    table.Apply({peer});
    ASSERT_EQ(table.Entries().size(), 1U);
    auto* original = &table.Entries().front();
    original->TxBytes = 123;
    peer.Endpoints({"192.0.2.1:12345"});

    table.Apply({peer});

    EXPECT_EQ(&table.Entries().front(), original);
    EXPECT_EQ(table.Entries().front().TxBytes, 123U);
    EXPECT_EQ(table.Entries().front().Config.Endpoints(), peer.Endpoints());
}

TEST(Given_PeerTable, When_PeerIsRemoved_Then_TransportDestinationAndRoutesAreWithdrawn)
{
    tailgate::ipn::ipnlocal::PeerTable table;
    table.Apply({Peer()});
    ASSERT_EQ(table.Entries().size(), 1U);

    table.Apply({});

    EXPECT_TRUE(table.Entries().empty());
    EXPECT_TRUE(table.Network().Peers().empty());
}

TEST(Given_PeerTable, When_NewPeerKeyIsInvalid_Then_NoEntryIsCreated)
{
    tailgate::ipn::ipnlocal::PeerTable table;
    auto peer = Peer();
    peer.Key("x");

    table.Apply({peer});

    EXPECT_TRUE(table.Entries().empty());
}

TEST(Given_PeerTable, When_ReplacementKeyIsInvalid_Then_ExistingIdentityIsPreserved)
{
    tailgate::ipn::ipnlocal::PeerTable table;
    auto peer = Peer();
    const auto originalKey = peer.Key();
    table.Apply({peer});
    ASSERT_EQ(table.Entries().size(), 1U);
    peer.Key("nodekey:" + std::string(64, 'z'));

    table.Apply({peer});

    EXPECT_EQ(table.Entries().front().Config.Key(), originalKey);
}
