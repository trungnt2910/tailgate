#include <algorithm>
#include <array>
#include <compare>
#include <string>

#include <gtest/gtest.h>

#include <tailgate/net/IpAddress.h>

namespace tailgate::tests
{

TEST(Given_IpAddress, When_AddressesAreOrdered_Then_FamilyAndNetworkBytesDetermineOrder)
{
    const auto ipv4 = net::IpAddress::Parse("192.0.2.9");
    const auto laterIpv4 = net::IpAddress::Parse("192.0.2.10");
    const auto ipv6 = net::IpAddress::Parse("2001:db8::9");
    const auto sameIpv6 = net::IpAddress::Parse("2001:0DB8:0:0:0:0:0:9");
    const auto laterIpv6 = net::IpAddress::Parse("2001:db8::10");

    const auto ipv4Order = ipv4 <=> laterIpv4;
    const auto familyOrder = laterIpv4 <=> ipv6;
    const auto ipv6Order = ipv6 <=> laterIpv6;
    const auto equality = ipv6 <=> sameIpv6;

    EXPECT_EQ(ipv4Order, std::strong_ordering::less);
    EXPECT_EQ(familyOrder, std::strong_ordering::less);
    EXPECT_EQ(ipv6Order, std::strong_ordering::less);
    EXPECT_EQ(equality, std::strong_ordering::equal);
}

TEST(Given_IpAddress, When_Ipv4IsParsed_Then_NetworkOrderBytesArePreserved)
{
    const std::string text = "192.0.2.19";

    const auto address = net::IpAddress::TryParse(text);
    ASSERT_TRUE(address);

    EXPECT_EQ(address->Family(), net::AddressFamily::Ipv4);
    EXPECT_EQ(address->ToString(), text);
    EXPECT_TRUE(std::ranges::equal(address->Bytes(), std::array<std::uint8_t, 4>{192, 0, 2, 19}));
}

TEST(Given_IpAddress, When_Ipv6IsParsed_Then_AddressRoundTrips)
{
    const std::string text = "2001:db8::19";

    const auto address = net::IpAddress::Parse(text);
    const auto decoded = net::IpAddress::TryParse(address.ToString());

    EXPECT_EQ(address.Family(), net::AddressFamily::Ipv6);
    EXPECT_EQ(decoded, address);
    EXPECT_EQ(address.Bytes().size(), 16U);
    EXPECT_EQ(address.Bytes().front(), 0x20U);
    EXPECT_EQ(address.Bytes().back(), 0x19U);
}

TEST(Given_IpAddress, When_TextContainsTrailingGarbage_Then_AddressIsRejected)
{
    const std::array<std::string, 8> texts{"2001:db8::1/64",
                                           "[2001:db8::1]",
                                           "fe80::1%2",
                                           "2001:db8::1 trailing",
                                           std::string("::1\0::2", 7),
                                           "::1\n",
                                           "256.0.0.1",
                                           "not an address"};

    std::array<bool, texts.size()> parsed{};
    for (std::size_t index = 0; index < texts.size(); ++index)
    {
        parsed[index] = net::IpAddress::TryParse(texts[index]).has_value();
    }

    EXPECT_EQ(parsed, (std::array<bool, texts.size()>{}));
}

TEST(Given_IpAddress, When_AddressIsUnspecified_Then_FamilyStillDistinguishesIt)
{
    const auto ipv4 = net::IpAddress::Parse("0.0.0.0");
    const auto ipv6 = net::IpAddress::Parse("::");

    const bool ipv4Unspecified = ipv4.IsUnspecified();
    const bool ipv6Unspecified = ipv6.IsUnspecified();

    EXPECT_TRUE(ipv4Unspecified);
    EXPECT_TRUE(ipv6Unspecified);
    EXPECT_NE(ipv4, ipv6);
}

} // namespace tailgate::tests
