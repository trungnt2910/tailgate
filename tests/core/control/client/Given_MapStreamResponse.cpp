#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/control/base/H2.h>

#include "MapStreamResponse.h"

class Given_MapStreamResponse : public testing::TestWithParam<std::vector<std::uint8_t>>
{
};

TEST_F(Given_MapStreamResponse, When_HttpErrorStreamEnds_Then_RejectionIsReported)
{
    tailgate::control::client::MapStreamResponse response;
    response.Start(3);
    response.ReceiveHeaders(tailgate::control::base::H2Headers{{":status", "500"}});
    response.ReceiveData(std::vector<std::uint8_t>{'f', 'a', 'i', 'l', 'e', 'd'});

    const auto finish = [&response]()
    {
        response.Finish();
    };

    EXPECT_THROW(finish(), tailgate::control::client::MapStreamRejected);
}

TEST_F(Given_MapStreamResponse, When_SuccessfulStreamEnds_Then_ClosureIsReported)
{
    tailgate::control::client::MapStreamResponse response;
    response.Start(3);
    response.ReceiveHeaders(tailgate::control::base::H2Headers{{":status", "200"}});

    const auto finish = [&response]()
    {
        response.Finish();
    };

    EXPECT_THROW(finish(), std::runtime_error);
}

TEST_F(Given_MapStreamResponse, When_LengthStartsWithJsonBrace_Then_LengthIsNotDecodedAsJson)
{
    constexpr std::size_t mapSize =
        static_cast<unsigned char>('{') + (static_cast<std::size_t>('l') << 8U);
    std::string json = R"({"Domain":"example.ts.net"})";
    json.resize(mapSize, ' ');
    std::vector<std::uint8_t> body{'{', 'l', 0, 0};
    body.insert(body.end(), json.begin(), json.end());

    const auto decoded = tailgate::control::client::MapStreamResponse::DecodeMap(body, mapSize);

    EXPECT_EQ(decoded, json);
}

TEST_F(Given_MapStreamResponse, When_SecondLengthByteIsJsonBrace_Then_LengthIsNotDecodedAsJson)
{
    constexpr std::size_t mapSize = static_cast<std::size_t>('{') << 8U;
    std::string json = R"({"Domain":"example.ts.net"})";
    json.resize(mapSize, ' ');
    std::vector<std::uint8_t> body{0, '{', 0, 0};
    body.insert(body.end(), json.begin(), json.end());

    const auto decoded = tailgate::control::client::MapStreamResponse::DecodeMap(body, mapSize);

    EXPECT_EQ(decoded, json);
}

TEST_F(Given_MapStreamResponse, When_CompleteMapHasLeadingWhitespace_Then_EntirePayloadIsDecoded)
{
    const std::string json = " \n{}";
    const std::vector<std::uint8_t> body{4, 0, 0, 0, ' ', '\n', '{', '}'};

    const auto decoded = tailgate::control::client::MapStreamResponse::DecodeMap(body, json.size());

    EXPECT_EQ(decoded, json);
}

TEST_P(Given_MapStreamResponse, When_DecodingInvalidFrame_Then_ResponseIsRejected)
{
    const auto& body = GetParam();
    constexpr std::size_t maximumSize = 128;

    const auto decode = [&body]()
    {
        return tailgate::control::client::MapStreamResponse::DecodeMap(body, maximumSize);
    };

    EXPECT_THROW(decode(), tailgate::control::client::InvalidMapResponse);
}

INSTANTIATE_TEST_SUITE_P(InvalidFrames,
                         Given_MapStreamResponse,
                         testing::Values(std::vector<std::uint8_t>{},
                                         std::vector<std::uint8_t>{2, 0, 0},
                                         std::vector<std::uint8_t>{0, 0, 0, 0},
                                         std::vector<std::uint8_t>{3, 0, 0, 0, '{', '}'},
                                         std::vector<std::uint8_t>{1, 0, 0, 0, '{', '}'},
                                         std::vector<std::uint8_t>{129, 0, 0, 0},
                                         std::vector<std::uint8_t>{'{', '}'}));

TEST_F(Given_MapStreamResponse, When_FrameArrivesInParts_Then_OnlyCompleteMapIsReturned)
{
    tailgate::control::client::MapStreamResponse response;
    response.Start(3);

    response.ReceiveData({2, 0});
    const auto partialLength = response.TakeMap(128);
    response.ReceiveData({0, 0, '{'});
    const auto partialBody = response.TakeMap(128);
    response.ReceiveData({'}', 2, 0, 0, 0, '{', '}'});
    const auto first = response.TakeMap(128);
    const auto second = response.TakeMap(128);
    const auto drained = response.TakeMap(128);

    EXPECT_FALSE(partialLength);
    EXPECT_FALSE(partialBody);
    EXPECT_EQ(first, "{}");
    EXPECT_EQ(second, "{}");
    EXPECT_FALSE(drained);
}
