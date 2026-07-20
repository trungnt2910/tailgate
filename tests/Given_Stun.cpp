#include <gtest/gtest.h>

#include "tailgate/protocol/Crypto.h"
#include "tailgate/protocol/Stun.h"

TEST(Given_StunTransaction, When_BuildingRequest_Then_TailscaleSoftwareAndFingerprintMatch)
{
    const tailgate::protocol::stun::TransactionId transaction{};

    const std::vector<std::uint8_t> request =
        tailgate::protocol::stun::BuildBindingRequest(transaction);

    EXPECT_EQ(tailgate::protocol::BytesToHex(request.data(), request.size()),
              "000100142112a442000000000000000000000000802200087461696c6e6f6465"
              "80280004fc8ee1af");
}

TEST(Given_StunIpv4Response, When_Parsing_Then_MappedEndpointIsReturned)
{
    const tailgate::protocol::stun::TransactionId transaction{
        0xeb, 0xc2, 0xd3, 0x6e, 0xf4, 0x71, 0x21, 0x7c, 0x4f, 0x3e, 0x30, 0x8e};
    const std::vector<std::uint8_t> response{
        0x01, 0x01, 0x00, 0x14, 0x21, 0x12, 0xa4, 0x42, 0xeb, 0xc2, 0xd3, 0x6e, 0xf4, 0x71,
        0x21, 0x7c, 0x4f, 0x3e, 0x30, 0x8e, 0x80, 0x22, 0x00, 0x01, 0x61, 0x00, 0x00, 0x00,
        0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xce, 0x66, 0x5e, 0x12, 0xa4, 0x43};

    const std::optional<std::string> endpoint =
        tailgate::protocol::stun::ParseMappedIpv4Endpoint(response, transaction);

    EXPECT_TRUE(endpoint.has_value());
    EXPECT_EQ(*endpoint, "127.0.0.1:61300");
}
