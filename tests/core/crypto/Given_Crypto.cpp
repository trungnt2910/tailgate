#include <algorithm>

#include <gtest/gtest.h>

#include <tailgate/protocol/Crypto.h>

TEST(Given_Crypto, When_DerivingPublicKey_Then_MatchesTailscaleVector)
{
    std::vector<std::uint8_t> privateBytes = tailgate::protocol::HexToBytes(
        "40ab1b58e9076c7a4d9d07291f5edf9d1aa017eb949624ba683317f48a640369");
    tailgate::protocol::Bytes32 privateKey{};
    std::copy(privateBytes.begin(), privateBytes.end(), privateKey.begin());

    tailgate::protocol::Bytes32 publicKey = tailgate::protocol::X25519PublicFromPrivate(privateKey);

    EXPECT_TRUE(tailgate::protocol::BytesToHex(publicKey.data(), publicKey.size()) ==
                "50d20b455ecf12bc453f83c2cfdb2a24925d06cf2598dcaa54e91af82ce9f765");
}

TEST(Given_Crypto, When_GeneratingPrivateKeys_Then_TheyAreClampedAndUnique)
{
    const auto first = tailgate::protocol::GeneratePrivateKey();
    const auto second = tailgate::protocol::GeneratePrivateKey();

    EXPECT_TRUE(first != second);
    EXPECT_TRUE((first[0] & 7U) == 0);
    EXPECT_TRUE((first[31] & 0x80U) == 0);
    EXPECT_TRUE((first[31] & 0x40U) != 0);
}
