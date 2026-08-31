#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/types/netmap/NetworkMap.h>
#include <tailgate/wgengine/router/Config.h>

namespace
{

constexpr tailgate::net::packet::Ipv4Prefix
    TailnetRoute(tailgate::net::Ipv4Address::FromOctets(100, 64, 0, 0).HostOrder(), 10);
constexpr tailgate::net::packet::Ipv4Prefix
    DnsRoute(tailgate::net::Ipv4Address::FromOctets(100, 100, 100, 100).HostOrder(), 32);

} // namespace

TEST(Given_RouterConfig, When_NetworkMapIsApplied_Then_LocalAddressesAndCoreRoutesAreProduced)
{
    tailgate::types::netmap::NetworkConfig networkMap;
    networkMap.SelfAddress("192.0.2.10");
    networkMap.SelfAddresses({"192.0.2.10", "2001:db8::10"});
    networkMap.DnsResolver("100.100.100.100");

    const tailgate::wgengine::router::Config result =
        tailgate::wgengine::router::Config::Build(networkMap);

    EXPECT_EQ(result.LocalAddresses(), (std::vector<std::string>{"192.0.2.10", "2001:db8::10"}));
    EXPECT_EQ(result.Routes(),
              (std::vector<tailgate::net::packet::Ipv4Prefix>{TailnetRoute, DnsRoute}));
}

TEST(Given_RouterConfig, When_ExitAndSubnetRoutesAreRequested_Then_RoutesAreNormalized)
{
    constexpr tailgate::net::packet::Ipv4Prefix LowerDefaultRoute(
        tailgate::net::Ipv4Address::FromOctets(0, 0, 0, 0).HostOrder(), 1);
    constexpr tailgate::net::packet::Ipv4Prefix UpperDefaultRoute(
        tailgate::net::Ipv4Address::FromOctets(128, 0, 0, 0).HostOrder(), 1);
    constexpr tailgate::net::packet::Ipv4Prefix SubnetRoute(
        tailgate::net::Ipv4Address::FromOctets(198, 51, 100, 0).HostOrder(), 24);
    constexpr tailgate::net::packet::Ipv4Prefix AdditionalRoute(
        tailgate::net::Ipv4Address::FromOctets(203, 0, 113, 53).HostOrder(), 32);
    tailgate::types::netmap::PeerConfig peer;
    peer.AllowedPrefixes({
        tailgate::net::packet::Ipv4Prefix(0, 0),
        TailnetRoute,
        SubnetRoute,
        SubnetRoute,
    });
    tailgate::types::netmap::NetworkConfig networkMap;
    networkMap.Peers({std::move(peer)});

    const tailgate::wgengine::router::Config result = tailgate::wgengine::router::Config::Build(
        networkMap,
        tailgate::wgengine::router::ConfigOptions{
            .AdditionalRoutes = {AdditionalRoute, AdditionalRoute},
            .RouteAllTraffic = true,
        });

    EXPECT_EQ(
        result.Routes(),
        (std::vector<tailgate::net::packet::Ipv4Prefix>{
            LowerDefaultRoute, TailnetRoute, UpperDefaultRoute, SubnetRoute, AdditionalRoute}));
}

TEST(Given_RouterConfig, When_InvalidOrDuplicateAddressesArePresent_Then_TheyAreExcluded)
{
    tailgate::types::netmap::NetworkConfig networkMap;
    networkMap.SelfAddress("192.0.2.10");
    networkMap.SelfAddresses({"", "192.0.2.10"});
    networkMap.DnsResolver("not-an-address");
    tailgate::types::netmap::PeerConfig peer;
    peer.AllowedPrefixes({tailgate::net::packet::Ipv4Prefix(
        tailgate::net::Ipv4Address::FromOctets(203, 0, 113, 0).HostOrder(), 33)});
    networkMap.Peers({std::move(peer)});

    const tailgate::wgengine::router::Config result =
        tailgate::wgengine::router::Config::Build(networkMap);

    EXPECT_EQ(result.LocalAddresses(), (std::vector<std::string>{"192.0.2.10"}));
    EXPECT_EQ(result.Routes(), (std::vector<tailgate::net::packet::Ipv4Prefix>{TailnetRoute}));
}
