#include <optional>
#include <string>

#include <gtest/gtest.h>

#include <tailgate/net/Endpoint.h>

TEST(Given_Endpoint, When_ValidIpv4EndpointIsParsed_Then_AddressPortAndTextRoundTrip)
{
    const std::string text = "192.0.2.10:41641";

    const std::optional<tailgate::net::Endpoint> endpoint = tailgate::net::Endpoint::TryParse(text);
    const tailgate::net::Endpoint parsed = endpoint.value_or(tailgate::net::Endpoint{});

    EXPECT_TRUE(endpoint.has_value());
    EXPECT_EQ(parsed.Address(), tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 10));
    EXPECT_EQ(parsed.Port(), 41641);
    EXPECT_EQ(parsed.ToString(), text);
}

TEST(Given_Endpoint, When_AddressOrPortIsInvalid_Then_ParseFails)
{
    const std::optional<tailgate::net::Endpoint> invalidAddress =
        tailgate::net::Endpoint::TryParse("192.0.2.256:41641");
    const std::optional<tailgate::net::Endpoint> missingPort =
        tailgate::net::Endpoint::TryParse("192.0.2.10");
    const std::optional<tailgate::net::Endpoint> overflowingPort =
        tailgate::net::Endpoint::TryParse("192.0.2.10:65536");

    EXPECT_FALSE(invalidAddress.has_value());
    EXPECT_FALSE(missingPort.has_value());
    EXPECT_FALSE(overflowingPort.has_value());
}

TEST(Given_Endpoint, When_InvalidTextIsParsedWithThrowingApi_Then_TypedFailureIsReturned)
{
    const auto parse = []()
    {
        (void)tailgate::net::Endpoint::Parse("192.0.2.10:65536");
    };

    EXPECT_THROW(parse(), tailgate::net::EndpointParseError);
}
