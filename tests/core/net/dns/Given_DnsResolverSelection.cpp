#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/dns/ResolverSelection.h>
#include <tailgate/types/netmap/NetworkMap.h>

TEST(Given_DnsResolverSelection, When_RoutesOverlap_Then_LongestSuffixWins)
{
    const std::vector<std::uint8_t> query =
        tailgate::net::dns::DnsQuery::Build("host.dev.example.ts.net", 1);
    const std::vector<tailgate::types::netmap::NetworkConfig::DnsRoute> routes{
        tailgate::types::netmap::NetworkConfig::DnsRoute{
            .Suffix = "example.ts.net",
            .Resolvers = {"100.64.0.10"},
        },
        tailgate::types::netmap::NetworkConfig::DnsRoute{
            .Suffix = "dev.example.ts.net",
            .Resolvers = {"100.64.0.20"},
        },
    };

    const auto result = tailgate::net::dns::SelectResolver(query, "100.100.100.100", routes, {});

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->Address, "100.64.0.20");
    EXPECT_TRUE(result->RouteMatched);
}

TEST(Given_DnsResolverSelection, When_NoRouteMatches_Then_DefaultResolverIsSelected)
{
    const std::vector<std::uint8_t> query =
        tailgate::net::dns::DnsQuery::Build("host.example.com", 1);
    const std::vector<tailgate::types::netmap::NetworkConfig::DnsRoute> routes;
    const std::vector<std::string> defaults{"192.0.2.53"};

    const auto result =
        tailgate::net::dns::SelectResolver(query, "100.100.100.100", routes, defaults);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->Address, "192.0.2.53");
    EXPECT_FALSE(result->RouteMatched);
}
