#include <gtest/gtest.h>

#include <tailgate/drive/Remote.h>

namespace tailgate::tests
{

class Given_DriveRemotes : public testing::Test
{
protected:
    Given_DriveRemotes()
    {
        m_config.Capabilities({"drive:access"});
        m_config.MagicDnsDomain("example.ts.net");
        m_config.SelfAddresses({"100.64.0.1", "2001:db8::1"});
        m_peer.NodeId(42);
        m_peer.Key("nodekey:" + std::string(64, 'a'));
        m_peer.Name("Laptop.example.ts.net.");
        m_peer.Online(true);
        m_peer.Capabilities({"tailscale.com/cap/drive-sharer"});
        m_peer.Addresses({"100.64.0.2", "2001:db8::2"});
        m_peer.PeerApi4Port(12345);
        m_peer.PeerApi6Port(23456);
    }

    types::netmap::NetworkConfig m_config;
    types::netmap::PeerConfig m_peer;
};

TEST_F(Given_DriveRemotes, When_PeerIsAvailable_Then_OnlyNetmapEndpointsAreReturned)
{
    m_config.Peers({m_peer});

    const auto remotes = drive::DiscoverRemotes(m_config);
    ASSERT_FALSE(remotes.empty());

    EXPECT_EQ(remotes.size(), 1U);
    EXPECT_EQ(remotes.front().Name, "laptop");
    EXPECT_EQ(remotes.front().NodeId, m_peer.NodeId());
    EXPECT_EQ(remotes.front().NodeKey, m_peer.Key());
    EXPECT_EQ(remotes.front().Ipv4, net::IpAddress::TryParse("100.64.0.2"));
    EXPECT_EQ(remotes.front().Ipv6, net::IpAddress::TryParse("2001:db8::2"));
    EXPECT_EQ(remotes.front().PeerApi4Port, 12345);
    EXPECT_EQ(remotes.front().PeerApi6Port, 23456);
}

TEST_F(Given_DriveRemotes, When_SelfAccessIsRevoked_Then_NoRemotesAreAvailable)
{
    m_config.Peers({m_peer});
    m_config.Capabilities({});

    const auto remotes = drive::DiscoverRemotes(m_config);

    EXPECT_TRUE(remotes.empty());
}

TEST_F(Given_DriveRemotes, When_PeerGrantIsRevoked_Then_RemoteIsUnavailable)
{
    m_peer.Capabilities({});
    m_config.Peers({m_peer});

    const auto remotes = drive::DiscoverRemotes(m_config);

    EXPECT_TRUE(remotes.empty());
}

TEST_F(Given_DriveRemotes, When_PeerIsOffline_Then_RemoteIsUnavailable)
{
    m_peer.Online(false);
    m_config.Peers({m_peer});

    const auto remotes = drive::DiscoverRemotes(m_config);

    EXPECT_TRUE(remotes.empty());
}

TEST_F(Given_DriveRemotes, When_PeerApiIsMissing_Then_RemoteIsUnavailable)
{
    m_peer.PeerApi4Port(0);
    m_peer.PeerApi6Port(0);
    m_config.Peers({m_peer});

    const auto remotes = drive::DiscoverRemotes(m_config);

    EXPECT_TRUE(remotes.empty());
}

TEST_F(Given_DriveRemotes, When_NoCommonAddressFamily_Then_RemoteIsUnavailable)
{
    m_peer.PeerApi4Port(0);
    m_config.SelfAddresses({"100.64.0.1"});
    m_config.Peers({m_peer});

    const auto remotes = drive::DiscoverRemotes(m_config);

    EXPECT_TRUE(remotes.empty());
}

TEST_F(Given_DriveRemotes, When_TwoPeersHaveTheSamePath_Then_AmbiguousNameIsOmitted)
{
    auto other = m_peer;
    other.NodeId(43);
    other.Name("laptop.example.ts.net");
    m_config.Peers({m_peer, other});

    const auto remotes = drive::DiscoverRemotes(m_config);

    EXPECT_TRUE(remotes.empty());
}

TEST_F(Given_DriveRemotes, When_NameContainsPathSyntax_Then_PeerCannotEscapeItsDirectory)
{
    m_peer.Name("../laptop.example.ts.net");
    m_config.Peers({m_peer});

    const auto remotes = drive::DiscoverRemotes(m_config);

    EXPECT_TRUE(remotes.empty());
}

TEST_F(Given_DriveRemotes, When_InvalidAddressHasAValidPort_Then_NoEndpointIsInvented)
{
    m_peer.Addresses({"https://example.com/", "0.0.0.0", "::"});
    m_config.Peers({m_peer});

    const auto remotes = drive::DiscoverRemotes(m_config);

    EXPECT_TRUE(remotes.empty());
}

} // namespace tailgate::tests
