#include <string>

#include <gtest/gtest.h>

#include <tailgate/crypto/PrefixedKey.h>

TEST(Given_PrefixedKey, When_KeyHasExpectedPrefixAndLength_Then_BytesAreDecoded)
{
    const std::string text = "nodekey:" + std::string(64, 'a');
    tailgate::crypto::Bytes32 expected{};
    expected.fill(0xaa);

    const auto key = tailgate::crypto::PrefixedKey::TryParse(text, "nodekey:");

    EXPECT_EQ(key, expected);
}

TEST(Given_PrefixedKey, When_PrefixIsForAnotherProtocol_Then_KeyIsRejected)
{
    const std::string text = "discokey:" + std::string(64, 'a');

    const auto key = tailgate::crypto::PrefixedKey::TryParse(text, "nodekey:");

    EXPECT_FALSE(key.has_value());
}

TEST(Given_PrefixedKey, When_LengthIsWrong_Then_KeyIsRejected)
{
    const std::string text = "nodekey:" + std::string(63, 'a');

    const auto key = tailgate::crypto::PrefixedKey::TryParse(text, "nodekey:");

    EXPECT_FALSE(key.has_value());
}

TEST(Given_PrefixedKey, When_HexIsInvalid_Then_KeyIsRejectedWithoutThrowing)
{
    const std::string text = "nodekey:" + std::string(64, 'z');

    const auto key = tailgate::crypto::PrefixedKey::TryParse(text, "nodekey:");

    EXPECT_FALSE(key.has_value());
}
