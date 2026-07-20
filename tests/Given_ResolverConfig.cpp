#include "tailgate/network/ResolverConfig.h"

#include <gtest/gtest.h>

TEST(Given_ResolverConfig, When_ApplyingAndRemovingSection_Then_PreservesHostConfiguration)
{
    const std::string original = "# host setting\nnameserver 192.0.2.53\noptions rotate\n";

    const std::string configured =
        tailgate::network::ApplyResolverSection(original, "127.0.0.1", {"tail.example"});
    const std::string restored = tailgate::network::RemoveResolverSection(configured);

    EXPECT_NE(configured.find("nameserver 127.0.0.1"), std::string::npos);
    EXPECT_NE(configured.find("search tail.example"), std::string::npos);
    EXPECT_EQ(restored, original);
}

TEST(Given_ResolverConfig, When_HostChangesOutsideSection_Then_RemovalPreservesChange)
{
    const std::string original = "nameserver 192.0.2.53\n";
    std::string configured = tailgate::network::ApplyResolverSection(original, "127.0.0.1", {});
    configured += "nameserver 198.51.100.53\n";

    const std::string restored = tailgate::network::RemoveResolverSection(configured);

    EXPECT_EQ(restored, original + "nameserver 198.51.100.53\n");
}

TEST(Given_ResolverConfig, When_ReadingResolvers_Then_IgnoresManagedSection)
{
    const std::string configured = tailgate::network::ApplyResolverSection(
        "nameserver 192.0.2.53\nnameserver 2001:db8::53\n", "127.0.0.1", {});

    const std::vector<std::string> resolvers = tailgate::network::ResolverAddresses(configured);

    EXPECT_EQ(resolvers.size(), 1U);
    EXPECT_EQ(resolvers.front(), "192.0.2.53");
}

TEST(Given_ResolverConfig, When_ApplyingTwice_Then_OnlyLatestSectionRemains)
{
    const std::string first =
        tailgate::network::ApplyResolverSection("nameserver 192.0.2.53\n", "127.0.0.1", {"one"});

    const std::string second = tailgate::network::ApplyResolverSection(first, "127.0.0.2", {"two"});

    EXPECT_EQ(second.find("nameserver 127.0.0.1"), std::string::npos);
    EXPECT_NE(second.find("nameserver 127.0.0.2"), std::string::npos);
    EXPECT_EQ(second.find("search one"), std::string::npos);
}
