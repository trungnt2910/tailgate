#include <gtest/gtest.h>

#include <tailgate/hosted/RelayEndpoint.h>

#include "fakes/types/nettype/FakeTcpSocket.h"

namespace tailgate
{
namespace
{

class Given_RelayEndpoint : public testing::Test
{
};

TEST_F(Given_RelayEndpoint, When_HttpsUrlHasExplicitPort_Then_HostAndServiceArePreserved)
{
    const std::string text = "https://relay.example.com:8443/";

    const auto endpoint = hosted::RelayEndpoint::Parse(text);

    EXPECT_EQ(endpoint.Host, "relay.example.com");
    EXPECT_EQ(endpoint.Port, "8443");
}

TEST_F(Given_RelayEndpoint, When_HttpsUrlHasNoPort_Then_DefaultTlsPortIsUsed)
{
    const std::string text = "https://relay.example.com/";

    const auto endpoint = hosted::RelayEndpoint::Parse(text);

    EXPECT_EQ(endpoint.Port, "443");
}

TEST_F(Given_RelayEndpoint, When_UrlIsCleartext_Then_EndpointIsRejected)
{
    const std::string text = "http://relay.example.com/";

    const auto parse = [&]()
    {
        (void)hosted::RelayEndpoint::Parse(text);
    };

    EXPECT_THROW(parse(), std::invalid_argument);
}

TEST_F(Given_RelayEndpoint, When_AddressIsLiteral_Then_NoResolverSocketIsNeeded)
{
    auto endpoint = hosted::RelayEndpoint::Parse("https://192.0.2.1/");
    tests::fakes::FakeTcpSocketFactory sockets;

    endpoint.Resolve(sockets, std::nullopt, 0);

    EXPECT_EQ(endpoint.ConnectAddress, "192.0.2.1");
}

TEST_F(Given_RelayEndpoint, When_ExplicitPortIsEmpty_Then_EndpointIsRejected)
{
    const std::string text = "https://relay.example.com:/";

    const auto parse = [&]()
    {
        (void)hosted::RelayEndpoint::Parse(text);
    };

    EXPECT_THROW(parse(), std::invalid_argument);
}

} // namespace

} // namespace tailgate
