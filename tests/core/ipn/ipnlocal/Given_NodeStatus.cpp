#include <gtest/gtest.h>

#include <tailgate/ipn/ipnlocal/NodeStatus.h>

namespace tailgate
{
namespace
{

class Given_NodeStatus : public testing::Test
{
protected:
    Given_NodeStatus()
    {
        Peer.Address("100.64.0.2");
        Peer.Name("peer.example.ts.net");
        Peer.Key("nodekey:" + std::string(64, '1'));
        Peer.Online(true);
        Peer.DerpRegion(1);
        Network.SelfAddress("100.64.0.1");
        Network.Peers({Peer});
        Subject.ApplyNetwork(Network);
    }

    Status State;
    ipn::ipnlocal::NodeStatus Subject{State};
    types::netmap::NetworkConfig Network;
    types::netmap::PeerConfig Peer;
};

TEST_F(Given_NodeStatus, When_PeerGoesOffline_Then_StaleTransportStateIsCleared)
{
    State.Peers.front().Direct = true;
    State.Peers.front().Active = true;
    State.Peers.front().Endpoint = "192.0.2.2:41641";
    State.Peers.front().TxBytes = 100;
    Peer.Online(false);
    Network.Peers({Peer});

    Subject.ApplyNetwork(Network);

    EXPECT_FALSE(State.Peers.front().Direct);
    EXPECT_FALSE(State.Peers.front().Active);
    EXPECT_TRUE(State.Peers.front().Endpoint.empty());
    EXPECT_EQ(State.Peers.front().TxBytes, 0U);
}

TEST_F(Given_NodeStatus, When_PeerMetadataChanges_Then_CurrentPathStatisticsRemain)
{
    State.Peers.front().Direct = true;
    State.Peers.front().TxBytes = 100;
    Peer.Name("renamed.example.ts.net");
    Network.Peers({Peer});

    Subject.ApplyNetwork(Network);

    EXPECT_TRUE(State.Peers.front().Direct);
    EXPECT_EQ(State.Peers.front().TxBytes, 100U);
    EXPECT_EQ(State.Peers.front().Hostname, "renamed");
}

TEST_F(Given_NodeStatus, When_PeerIsRemoved_Then_OnlyThatStatusIsRemoved)
{
    State.ProcessId = 123;
    Network.Peers({});

    Subject.ApplyNetwork(Network);

    EXPECT_TRUE(State.Peers.empty());
    EXPECT_EQ(State.ProcessId, 123);
    EXPECT_TRUE(State.Online);
}

} // namespace

} // namespace tailgate
