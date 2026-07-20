#include "tailgate/protocol/Crypto.h"
#include "tailgate/protocol/DerpClient.h"

#include <algorithm>
#include <gtest/gtest.h>
#include <vector>

TEST(Given_DerpServerKey, When_BuildingClientInfo_Then_EnvelopeContainsNodeKeyAndFreshNonce)
{
    const tailgate::protocol::Bytes32 clientPrivate = tailgate::protocol::GeneratePrivateKey();
    const tailgate::protocol::Bytes32 clientPublic =
        tailgate::protocol::X25519PublicFromPrivate(clientPrivate);
    const tailgate::protocol::Bytes32 serverPublic =
        tailgate::protocol::X25519PublicFromPrivate(tailgate::protocol::GeneratePrivateKey());

    const std::vector<std::uint8_t> first =
        tailgate::protocol::DerpClient::BuildClientInfo(clientPrivate, clientPublic, serverPublic);
    const std::vector<std::uint8_t> second =
        tailgate::protocol::DerpClient::BuildClientInfo(clientPrivate, clientPublic, serverPublic);

    EXPECT_GT(first.size(), clientPublic.size());
    EXPECT_EQ(first.size(), second.size());
    EXPECT_TRUE(std::equal(clientPublic.begin(), clientPublic.end(), first.begin()));
    EXPECT_TRUE(std::equal(clientPublic.begin(), clientPublic.end(), second.begin()));
    EXPECT_NE(first, second);
}
