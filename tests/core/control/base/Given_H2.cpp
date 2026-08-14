#include <algorithm>
#include <format>
#include <optional>
#include <ranges>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/control/base/H2.h>

TEST(Given_HuffmanEncoded410Status, When_DecodingH2Headers_Then_StatusIsReturned)
{
    const std::vector<std::uint8_t> headerBlock{0x4e, 0x82, 0x68, 0x20};

    const auto status = tailgate::control::base::DecodeH2Status(headerBlock);

    EXPECT_EQ(status, 410);
}

TEST(Given_HuffmanEncoded429Status, When_DecodingH2Headers_Then_StatusIsReturned)
{
    const std::vector<std::uint8_t> headerBlock{0x4e, 0x83, 0x68, 0x4f, 0xff};

    const auto status = tailgate::control::base::DecodeH2Status(headerBlock);

    EXPECT_EQ(status, 429);
}

TEST(Given_HuffmanEncodedRetryAfter, When_DecodingH2Headers_Then_HeaderIsReturned)
{
    const std::vector<std::uint8_t> headerBlock{
        0x4e,
        0x83,
        0x68,
        0x4f,
        0xff,
        0x75,
        0x82,
        0x64,
        0x1f,
    };

    const auto headers = tailgate::control::base::DecodeH2Headers(headerBlock);
    ASSERT_TRUE(headers.has_value());
    const auto retryAfter = headers->find("retry-after");

    ASSERT_NE(retryAfter, headers->end());
    EXPECT_EQ(retryAfter->second, "30");
}

TEST(Given_IndexedDynamicResponseHeaders, When_DecodingNextBlock_Then_HeadersAreReturned)
{
    tailgate::control::base::H2HeaderDecoder decoder;
    const std::vector<std::uint8_t> literalHeaderBlock{
        0x4e,
        0x83,
        0x68,
        0x4f,
        0xff,
        0x75,
        0x82,
        0x64,
        0x1f,
    };
    const std::vector<std::uint8_t> indexedHeaderBlock{0xbf, 0xbe};
    ASSERT_TRUE(decoder.Decode(literalHeaderBlock).has_value());

    const auto headers = decoder.Decode(indexedHeaderBlock);
    ASSERT_TRUE(headers.has_value());
    const auto status = headers->find(":status");
    const auto retryAfter = headers->find("retry-after");

    ASSERT_NE(status, headers->end());
    ASSERT_NE(retryAfter, headers->end());
    EXPECT_EQ(status->second, "429");
    EXPECT_EQ(retryAfter->second, "30");
}

TEST(Given_LiteralMaximumHttpStatus, When_DecodingH2Headers_Then_StatusIsReturned)
{
    const std::vector<std::uint8_t> headerBlock{0x4e, 0x03, '5', '9', '9'};

    const auto status = tailgate::control::base::DecodeH2Status(headerBlock);

    EXPECT_EQ(status, 599);
}

TEST(Given_EveryValidHttpStatus, When_DecodingH2Headers_Then_StatusIsReturned)
{
    std::vector<std::vector<std::uint8_t>> headerBlocks;
    for (int status = 100; status <= 599; ++status)
    {
        const std::string value = std::format("{}", status);
        std::vector<std::uint8_t> headerBlock{0x4e, 0x03};
        headerBlock.insert(headerBlock.end(), value.begin(), value.end());
        headerBlocks.push_back(std::move(headerBlock));
    }

    std::vector<std::optional<int>> decodedStatuses;
    decodedStatuses.reserve(headerBlocks.size());
    for (const auto& headerBlock : headerBlocks)
    {
        decodedStatuses.push_back(tailgate::control::base::DecodeH2Status(headerBlock));
    }

    const bool allStatusesMatch =
        std::ranges::equal(decodedStatuses,
                           std::views::iota(100, 600),
                           [](const std::optional<int>& actual, int expected)
                           {
                               return actual == expected;
                           });
    EXPECT_TRUE(allStatusesMatch);
}

TEST(Given_OutOfRangeHttpStatus, When_DecodingH2Headers_Then_StatusIsRejected)
{
    const std::vector<std::uint8_t> headerBlock{0x4e, 0x03, '6', '0', '0'};

    const auto status = tailgate::control::base::DecodeH2Status(headerBlock);

    EXPECT_FALSE(status.has_value());
}
