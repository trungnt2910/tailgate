#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/ipn/ipnlocal/DerpConnections.h>
#include <tailgate/ipn/ipnlocal/NodeError.h>

#include "fakes/derp/FakeConnection.h"
#include "fakes/di/FakeNetworkBindings.h"

namespace
{

class Given_DerpConnections : public testing::Test,
                              public tailgate::ipn::ipnlocal::DerpTransportFactory
{
protected:
    void SetNetworkInterface(const std::string&) override
    {
    }

    Given_DerpConnections()
    {
        tailgate::tests::fakes::InstallFakeNetworkBindings(Injector);
        Connections = std::make_unique<tailgate::ipn::ipnlocal::DerpConnections>(
            Injector.create<tailgate::wgengine::Session&>(), *this);
    }

    std::unique_ptr<tailgate::derp::Connection>
    Create(int region, const std::string&, bool, std::size_t index, bool enabled) override
    {
        Regions.push_back(region);
        auto result = std::make_unique<tailgate::tests::fakes::derp::FakeConnection>(
            tailgate::base::EventToken{.Value = index + 1}, tailgate::derp::DerpClient::Packet{});
        result->SetEnabled(enabled);
        return result;
    }

    tailgate::di::Injector Injector;
    std::vector<int> Regions;
    std::unique_ptr<tailgate::ipn::ipnlocal::DerpConnections> Connections;
};

} // namespace

TEST_F(Given_DerpConnections, When_PeersShareRegion_Then_OneTransportIsProvisioned)
{
    tailgate::types::netmap::NetworkConfig network;
    network.DerpRegion(1);
    network.DerpHost("home.example.com");
    tailgate::types::netmap::PeerConfig peer;
    peer.DerpRegion(2);
    peer.DerpHost("peer.example.com");
    network.Peers({peer, peer});

    Connections->ApplyNetworkMap(network);
    Connections->ApplyNetworkMap(network);

    EXPECT_EQ(Regions, (std::vector<int>{1, 2}));
    EXPECT_EQ(Connections->Entries().size(), 2U);
}

TEST_F(Given_DerpConnections, When_NewRegionIsAdded_Then_ExistingIngressRouteStaysValid)
{
    Connections->Ensure(1, "home.example.com", true);
    const auto route = Connections->Entries().front().Route;
    auto* original = &Connections->ForRegion(1);

    Connections->Ensure(2, "peer.example.com", false);

    EXPECT_EQ(Connections->ForRoute(route), original);
    EXPECT_EQ(&Connections->ForRegion(99), original);
    EXPECT_NE(&Connections->ForRegion(2), original);
}

TEST_F(Given_DerpConnections, When_RegionIsInvalid_Then_TransportIsNotOpened)
{
    const auto ensure = [&]()
    {
        Connections->Ensure(0, "home.example.com", false);
    };

    EXPECT_THROW(ensure(), tailgate::ipn::ipnlocal::NodeError);
    EXPECT_TRUE(Regions.empty());
}
