#include <array>
#include <string_view>

#include <gtest/gtest.h>

#include <tailgate/net/IpRange.h>

namespace tailgate::tests
{

TEST(Given_IpRange, When_PrefixContainsHostBits_Then_RangeIsNormalized)
{
    const auto range = net::IpRange::TryParse("192.0.2.99/24");
    ASSERT_TRUE(range.has_value());

    const bool first = range->Contains(net::IpAddress::Parse("192.0.2.0"));
    const bool last = range->Contains(net::IpAddress::Parse("192.0.2.255"));
    const bool outside = range->Contains(net::IpAddress::Parse("192.0.3.0"));

    EXPECT_TRUE(first);
    EXPECT_TRUE(last);
    EXPECT_FALSE(outside);
}

TEST(Given_IpRange, When_Ipv6IntervalIsParsed_Then_EndpointsAreInclusive)
{
    const auto range = net::IpRange::TryParse("2001:db8::10-2001:db8::20");
    ASSERT_TRUE(range.has_value());

    const bool first = range->Contains(net::IpAddress::Parse("2001:db8::10"));
    const bool last = range->Contains(net::IpAddress::Parse("2001:db8::20"));
    const bool outside = range->Contains(net::IpAddress::Parse("2001:db8::21"));

    EXPECT_TRUE(first);
    EXPECT_TRUE(last);
    EXPECT_FALSE(outside);
}

TEST(Given_IpRange, When_InputIsMalformed_Then_ParsingFails)
{
    const std::array<std::string_view, 8> inputs{"192.0.2.1/33",
                                                 "2001:db8::1/129",
                                                 "192.0.2.1/",
                                                 "192.0.2.1/-1",
                                                 "192.0.2.1/+1",
                                                 "192.0.2.1/24x",
                                                 "192.0.2.2-192.0.2.1",
                                                 "192.0.2.1-::1"};

    std::array<bool, inputs.size()> accepted{};
    for (std::size_t index = 0; index < inputs.size(); ++index)
    {
        accepted[index] = net::IpRange::TryParse(inputs[index]).has_value();
    }

    EXPECT_EQ(accepted, (std::array<bool, inputs.size()>{}));
}

} // namespace tailgate::tests
