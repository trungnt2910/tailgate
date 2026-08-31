#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <string>

#include <gtest/gtest.h>

#include <tailgate/net/Ipv4Address.h>

TEST(Given_Ipv4Address, When_ConstructedFromOctets_Then_HostOrderAndOctetsRoundTrip)
{
    const tailgate::net::Ipv4Address address = tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 1);

    const std::array<std::uint8_t, 4> octets = address.Octets();

    EXPECT_EQ(octets, (std::array<std::uint8_t, 4>{192, 0, 2, 1}));
    EXPECT_EQ(tailgate::net::Ipv4Address::FromHostOrder(address.HostOrder()), address);
}

TEST(Given_Ipv4Address, When_ValidTextIsParsed_Then_AddressAndTextRoundTrip)
{
    const std::string text = "198.51.100.2";

    const std::optional<tailgate::net::Ipv4Address> address =
        tailgate::net::Ipv4Address::TryParse(text);

    ASSERT_TRUE(address.has_value());
    EXPECT_EQ(address->ToString(), text);
}

TEST(Given_Ipv4Address, When_OctetIsOutOfRange_Then_ParseFails)
{
    const std::string text = "192.0.2.256";

    const std::optional<tailgate::net::Ipv4Address> address =
        tailgate::net::Ipv4Address::TryParse(text);

    EXPECT_FALSE(address.has_value());
}

TEST(Given_Ipv4Address, When_PrivateRangesAreClassified_Then_OnlyRfc1918AddressesMatch)
{
    constexpr std::array privateAddresses{
        tailgate::net::Ipv4Address::FromOctets(10, 0, 0, 1),
        tailgate::net::Ipv4Address::FromOctets(172, 16, 0, 1),
        tailgate::net::Ipv4Address::FromOctets(172, 31, 255, 254),
        tailgate::net::Ipv4Address::FromOctets(192, 168, 1, 1),
    };
    constexpr std::array publicAddresses{
        tailgate::net::Ipv4Address::FromOctets(9, 255, 255, 255),
        tailgate::net::Ipv4Address::FromOctets(172, 15, 255, 255),
        tailgate::net::Ipv4Address::FromOctets(172, 32, 0, 0),
        tailgate::net::Ipv4Address::FromOctets(192, 169, 0, 0),
    };

    const bool privateMatches = std::ranges::all_of(privateAddresses,
                                                    [](const auto& address)
                                                    {
                                                        return address.IsPrivate();
                                                    });
    const bool publicMatches = std::ranges::any_of(publicAddresses,
                                                   [](const auto& address)
                                                   {
                                                       return address.IsPrivate();
                                                   });

    EXPECT_TRUE(privateMatches);
    EXPECT_FALSE(publicMatches);
}

TEST(Given_Ipv4Address, When_InvalidTextIsParsedWithThrowingApi_Then_TypedFailureIsReturned)
{
    const auto parse = []()
    {
        (void)tailgate::net::Ipv4Address::Parse("192.0.2.256");
    };

    EXPECT_THROW(parse(), tailgate::net::Ipv4AddressParseError);
}
