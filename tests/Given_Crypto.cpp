#include <gtest/gtest.h>

#include "tailgate/protocol/Crypto.h"
#include "tailgate/protocol/Noise.h"

#include <algorithm>

TEST(Tailgate, GivenCrypto_WhenDerivingPublicKey_ThenMatchesTailscaleVector)
{
    std::vector<std::uint8_t> privateBytes = tailgate::protocol::HexToBytes(
        "40ab1b58e9076c7a4d9d07291f5edf9d1aa017eb949624ba683317f48a640369");
    tailgate::protocol::Bytes32 privateKey{};
    std::copy(privateBytes.begin(), privateBytes.end(), privateKey.begin());

    tailgate::protocol::Bytes32 publicKey = tailgate::protocol::X25519PublicFromPrivate(privateKey);

    ASSERT_TRUE(tailgate::protocol::BytesToHex(publicKey.data(), publicKey.size()) ==
                "50d20b455ecf12bc453f83c2cfdb2a24925d06cf2598dcaa54e91af82ce9f765");
}

TEST(Tailgate, GivenNoiseInitiator_WhenWritingMessage1_ThenFrameShapeMatchesTs2021)
{
    tailgate::protocol::Bytes32 machinePrivate{};
    tailgate::protocol::Bytes32 ephemeralPrivate{};
    machinePrivate[0] = 1;
    ephemeralPrivate[0] = 2;

    tailgate::protocol::NoiseInitiator noise(machinePrivate, ephemeralPrivate);
    std::vector<std::uint8_t> message = noise.WriteMessage1();

    ASSERT_TRUE(message.size() == 101);
    ASSERT_TRUE(message[0] == 0);
    ASSERT_TRUE(message[1] == 131);
    ASSERT_TRUE(message[2] == 1);
    ASSERT_TRUE(message[3] == 0);
    ASSERT_TRUE(message[4] == 96);
}

TEST(Tailgate, GivenCrypto_WhenGeneratingPrivateKeys_ThenTheyAreClampedAndUnique)
{
    const auto first = tailgate::protocol::GeneratePrivateKey();
    const auto second = tailgate::protocol::GeneratePrivateKey();

    ASSERT_TRUE(first != second);
    ASSERT_TRUE((first[0] & 7U) == 0);
    ASSERT_TRUE((first[31] & 0x80U) == 0);
    ASSERT_TRUE((first[31] & 0x40U) != 0);
}
