#include <algorithm>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "manager/ChannelPolicy.h"

namespace tailgate::uwp::tests
{
namespace
{

using bg::manager::ChannelPolicy;
using tailgate::types::netmap::NetworkConfig;
using tailgate::types::netmap::PeerConfig;

NetworkConfig Network()
{
    NetworkConfig config;
    config.SelfAddress("192.0.2.1");
    config.SelfAddresses({"192.0.2.1", "2001:db8::1", "2001:db8::2"});
    config.DnsDomains({"example.ts.net"});
    config.DnsRoutes({{.Suffix = "example.com", .Resolvers = {"192.0.2.53"}}});
    return config;
}

TEST(Given_ChannelPolicy, When_PeerNamesKeysAndPathsChange_Then_ChannelPolicyIsUnchanged)
{
    const auto before = Network();
    auto after = before;
    PeerConfig peer;
    peer.Name("renamed.example.ts.net");
    peer.Key("nodekey:" + std::string(64, '1'));
    peer.Endpoints({"192.0.2.2:41641"});
    peer.DerpRegion(1);
    peer.Online(true);
    after.Peers({peer});

    const auto installed = ChannelPolicy::Build(before, false);
    const auto updated = ChannelPolicy::Build(after, false);

    EXPECT_EQ(installed, updated);
}

TEST(Given_ChannelPolicy, When_Ipv4AssignmentChanges_Then_ChannelPolicyChanges)
{
    const auto before = Network();
    auto after = before;
    after.SelfAddress("192.0.2.2");

    const auto installed = ChannelPolicy::Build(before, false);
    const auto updated = ChannelPolicy::Build(after, false);

    EXPECT_NE(installed, updated);
}

TEST(Given_ChannelPolicy, When_Ipv6AssignmentChanges_Then_ChannelPolicyChanges)
{
    const auto before = Network();
    auto after = before;
    after.SelfAddresses({"192.0.2.1", "2001:db8::3"});

    const auto installed = ChannelPolicy::Build(before, false);
    const auto updated = ChannelPolicy::Build(after, false);

    EXPECT_NE(installed, updated);
}

TEST(Given_ChannelPolicy, When_AddressOrderChanges_Then_ChannelPolicyIsUnchanged)
{
    const auto before = Network();
    auto after = before;
    auto addresses = after.SelfAddresses();
    std::reverse(addresses.begin(), addresses.end());
    after.SelfAddresses(addresses);

    const auto installed = ChannelPolicy::Build(before, false);
    const auto updated = ChannelPolicy::Build(after, false);

    EXPECT_EQ(installed, updated);
}

TEST(Given_ChannelPolicy, When_SubnetRouteIsAdded_Then_ChannelPolicyChanges)
{
    const auto before = Network();
    auto after = before;
    PeerConfig peer;
    const auto route = tailgate::net::packet::Ipv4Prefix::Parse("198.51.100.0/24");
    ASSERT_TRUE(route.has_value());
    peer.AllowedPrefixes({*route});
    after.Peers({peer});

    const auto installed = ChannelPolicy::Build(before, false);
    const auto updated = ChannelPolicy::Build(after, false);

    EXPECT_NE(installed, updated);
}

TEST(Given_ChannelPolicy, When_ExitNodeIsEnabled_Then_ChannelPolicyChanges)
{
    const auto network = Network();

    const auto installed = ChannelPolicy::Build(network, false);
    const auto updated = ChannelPolicy::Build(network, true);

    EXPECT_NE(installed, updated);
}

TEST(Given_ChannelPolicy, When_DnsSuffixChanges_Then_ChannelPolicyChanges)
{
    const auto before = Network();
    auto after = before;
    after.DnsDomains({"new.example.ts.net"});

    const auto installed = ChannelPolicy::Build(before, false);
    const auto updated = ChannelPolicy::Build(after, false);

    EXPECT_NE(installed, updated);
}

TEST(Given_ChannelPolicy, When_DnsResolverChanges_Then_ChannelPolicyChanges)
{
    const auto before = Network();
    auto after = before;
    after.DnsRoutes({{.Suffix = "example.com", .Resolvers = {"192.0.2.54"}}});

    const auto installed = ChannelPolicy::Build(before, false);
    const auto updated = ChannelPolicy::Build(after, false);

    EXPECT_NE(installed, updated);
}

TEST(Given_ChannelPolicy, When_DnsResolverOrderChanges_Then_ChannelPolicyChanges)
{
    auto before = Network();
    before.DnsRoutes({{.Suffix = "example.com", .Resolvers = {"192.0.2.53", "192.0.2.54"}}});
    auto after = before;
    after.DnsRoutes({{.Suffix = "example.com", .Resolvers = {"192.0.2.54", "192.0.2.53"}}});

    const auto installed = ChannelPolicy::Build(before, false);
    const auto updated = ChannelPolicy::Build(after, false);

    EXPECT_NE(installed, updated);
}

TEST(Given_ChannelPolicy, When_DnsNamesHaveTrailingDots_Then_EffectivePolicyIsUnchanged)
{
    const auto before = Network();
    auto after = before;
    after.DnsDomains({"example.ts.net."});
    after.DnsRoutes({{.Suffix = "example.com.", .Resolvers = {"192.0.2.53"}}});

    const auto installed = ChannelPolicy::Build(before, false);
    const auto updated = ChannelPolicy::Build(after, false);

    EXPECT_EQ(installed, updated);
}

TEST(Given_ChannelPolicy, When_DuplicateOrInvalidDnsSuffixIsAdded_Then_EffectivePolicyIsUnchanged)
{
    const auto before = Network();
    auto after = before;
    after.DnsDomains({"example.ts.net", "example.ts.net", "", "bad..example.com"});

    const auto installed = ChannelPolicy::Build(before, false);
    const auto updated = ChannelPolicy::Build(after, false);

    EXPECT_EQ(installed, updated);
}

TEST(Given_ChannelPolicy, When_DnsSearchDomainOrderChanges_Then_ChannelPolicyChanges)
{
    auto before = Network();
    before.DnsDomains({"example.ts.net", "example.trungnt2910.com"});
    auto after = before;
    after.DnsDomains({"example.trungnt2910.com", "example.ts.net"});

    const auto installed = ChannelPolicy::Build(before, false);
    const auto updated = ChannelPolicy::Build(after, false);

    EXPECT_NE(installed, updated);
}

} // namespace
} // namespace tailgate::uwp::tests
