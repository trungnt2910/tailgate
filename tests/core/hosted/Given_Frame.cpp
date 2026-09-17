#include <cstdint>
#include <stdexcept>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/hosted/Protocol.h>

namespace
{

using tailgate::hosted::Frame;
using tailgate::hosted::MessageType;

TEST(Given_Frame, When_EmptyBatchIsEncoded_Then_OutputIsEmpty)
{
    const std::vector<Frame> frames;

    const auto encoded = Frame::EncodeAll(frames);

    EXPECT_TRUE(encoded.empty());
}

TEST(Given_Frame, When_MixedBatchIsEncoded_Then_ExactWireBytesAndOrderArePreserved)
{
    const std::vector<Frame> frames{
        Frame(MessageType::Heartbeat, {}),
        Frame(MessageType::ServerPacket, {0, 0xff, 0x42}),
        Frame(MessageType::Pump, {7}),
    };
    const std::vector<std::uint8_t> expected{
        'T', 'G', 'R', '1', 0, 10,   0,    0,   0,   0,   0,   0, 'T', 'G', 'R', '1', 0, 6, 0, 0,
        0,   0,   0,   3,   0, 0xff, 0x42, 'T', 'G', 'R', '1', 0, 22,  0,   0,   0,   0, 0, 1, 7,
    };

    const auto encoded = Frame::EncodeAll(frames);

    EXPECT_EQ(encoded, expected);
}

TEST(Given_Frame, When_BatchExceedsSingleFrameLimit_Then_EachMaximumFrameIsPreserved)
{
    const std::vector<Frame> frames{
        Frame(MessageType::ServerPacket, std::vector<std::uint8_t>(Frame::MaximumPayloadSize, 1)),
        Frame(MessageType::ServerPacket, std::vector<std::uint8_t>(Frame::MaximumPayloadSize, 2)),
    };
    auto expected = frames[0].Encode();
    const auto second = frames[1].Encode();
    expected.insert(expected.end(), second.begin(), second.end());

    const auto encoded = Frame::EncodeAll(frames);

    EXPECT_EQ(encoded.size(), 2 * Frame::MaximumEncodedSize);
    EXPECT_EQ(encoded, expected);
}

TEST(Given_Frame, When_LaterFrameHasUnknownType_Then_BatchIsRejected)
{
    const std::vector<Frame> frames{
        Frame(MessageType::Heartbeat, {}),
        Frame(static_cast<MessageType>(0), {}),
    };

    const auto encode = [&]()
    {
        return Frame::EncodeAll(frames);
    };

    EXPECT_THROW((void)encode(), std::runtime_error);
}

TEST(Given_Frame, When_LaterFramePayloadExceedsLimit_Then_BatchIsRejected)
{
    const std::vector<Frame> frames{
        Frame(MessageType::Heartbeat, {}),
        Frame(MessageType::ServerPacket,
              std::vector<std::uint8_t>(Frame::MaximumPayloadSize + 1, 1)),
    };

    const auto encode = [&]()
    {
        return Frame::EncodeAll(frames);
    };

    EXPECT_THROW((void)encode(), std::runtime_error);
}

} // namespace
