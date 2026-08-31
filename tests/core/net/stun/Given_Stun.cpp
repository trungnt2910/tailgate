#include <gtest/gtest.h>

#include <algorithm>
#include <array>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/net/stun/Stun.h>

#include "fakes/crypto/FakeRandom.h"

TEST(Given_Stun, When_StunTransactionAndBuildingRequest_Then_TailscaleSoftwareAndFingerprintMatch)
{
    const tailgate::net::stun::TransactionId transaction{};

    const std::vector<std::uint8_t> request = transaction.BuildBindingRequest();

    EXPECT_EQ(tailgate::crypto::BytesToHex(request.data(), request.size()),
              "000100142112a442000000000000000000000000802200087461696c6e6f6465"
              "80280004fc8ee1af");
}

TEST(Given_Stun, When_StunIpv4ResponseAndParsing_Then_MappedEndpointIsReturned)
{
    const tailgate::net::stun::TransactionId transaction(std::array<std::uint8_t, 12>{
        0xeb, 0xc2, 0xd3, 0x6e, 0xf4, 0x71, 0x21, 0x7c, 0x4f, 0x3e, 0x30, 0x8e});
    const std::vector<std::uint8_t> response{
        0x01, 0x01, 0x00, 0x14, 0x21, 0x12, 0xa4, 0x42, 0xeb, 0xc2, 0xd3, 0x6e, 0xf4, 0x71,
        0x21, 0x7c, 0x4f, 0x3e, 0x30, 0x8e, 0x80, 0x22, 0x00, 0x01, 0x61, 0x00, 0x00, 0x00,
        0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xce, 0x66, 0x5e, 0x12, 0xa4, 0x43};

    const std::optional<tailgate::net::Endpoint> endpoint =
        transaction.ParseMappedIpv4Endpoint(response);

    EXPECT_TRUE(endpoint.has_value());
    if (endpoint)
    {
        EXPECT_EQ(endpoint->Address(), tailgate::net::Ipv4Address::FromOctets(127, 0, 0, 1));
        EXPECT_EQ(endpoint->Port(), 61300);
        EXPECT_EQ(endpoint->ToString(), "127.0.0.1:61300");
    }
}
