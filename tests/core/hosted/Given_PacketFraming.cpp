#include <algorithm>
#include <array>
#include <cstdint>
#include <numeric>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/hosted/PacketFraming.h>
#include <tailgate/hosted/Protocol.h>

namespace tailgate::tests
{
namespace
{

using tailgate::hosted::Decoder;
using tailgate::hosted::Frame;
using tailgate::hosted::MessageType;
using tailgate::hosted::PacketEncoder;
using tailgate::hosted::PacketFramingError;
using tailgate::hosted::PacketReassembler;
constexpr std::size_t VpnBufferCapacity = 1500;

std::vector<std::vector<std::uint8_t>> Drain(PacketEncoder& encoder)
{
    std::vector<std::vector<std::uint8_t>> result;
    while (encoder.HasPending())
    {
        result.push_back(encoder.Next(VpnBufferCapacity));
    }
    return result;
}

std::vector<std::uint8_t> Fragment(std::uint64_t offset, std::size_t size)
{
    std::vector<std::uint8_t> result(PacketEncoder::OffsetSize + size, 0);
    for (std::size_t index = 0; index < PacketEncoder::OffsetSize; ++index)
    {
        constexpr unsigned BitsPerByte = 8;
        const auto shift =
            static_cast<unsigned>((PacketEncoder::OffsetSize - index - 1) * BitsPerByte);
        result[index] = static_cast<std::uint8_t>(offset >> shift);
    }
    return result;
}

TEST(Given_PacketEncoder, When_BufferIsTooSmall_Then_QueuedBytesArePreserved)
{
    PacketEncoder encoder;
    const auto frame = Frame(MessageType::Heartbeat, {}).Encode();
    encoder.Queue(frame);

    EXPECT_THROW((void)encoder.Next(Frame::HeaderSize + PacketEncoder::OffsetSize),
                 PacketFramingError);
    EXPECT_TRUE(encoder.HasPending());
}

TEST(Given_PacketEncoder, When_QueueExceedsLimit_Then_InputIsRejected)
{
    PacketEncoder encoder;
    encoder.Queue(std::vector<std::uint8_t>(PacketEncoder::MaximumPendingBytes));

    EXPECT_THROW(encoder.Queue({1}), PacketFramingError);
}

TEST(Given_PacketEncoder, When_EmptyInputIsQueued_Then_NoTransportPacketIsGenerated)
{
    PacketEncoder encoder;

    encoder.Queue({});
    const auto result = encoder.Next(VpnBufferCapacity);

    EXPECT_TRUE(result.empty());
    EXPECT_FALSE(encoder.HasPending());
}

TEST(Given_PacketEncoder, When_MapAndControlCallbacksInterleave_Then_OriginalFrameOrderIsRestored)
{
    PacketEncoder encoder;
    Decoder decoder;
    const Frame map(MessageType::NetworkMap, std::vector<std::uint8_t>(9600, 'x'));
    const Frame control(MessageType::Heartbeat, {});
    const Frame data(MessageType::ClientPacket, std::vector<std::uint8_t>(1280, 'y'));
    encoder.Queue(map.Encode());
    auto mapPackets = Drain(encoder);
    encoder.Queue(control.Encode());
    auto controlPackets = Drain(encoder);
    encoder.Queue(data.Encode());
    auto dataPackets = Drain(encoder);
    ASSERT_GT(mapPackets.size(), 1U);
    ASSERT_EQ(controlPackets.size(), 1U);
    ASSERT_EQ(dataPackets.size(), 1U);
    std::vector<Frame> frames;

    decoder.Feed(mapPackets.front());
    const auto partial = decoder.Next();
    decoder.Feed(controlPackets.front());
    const auto interleavedControl = decoder.Next();
    decoder.Feed(dataPackets.front());
    const auto interleavedData = decoder.Next();
    for (std::size_t index = mapPackets.size(); index-- > 1;)
    {
        decoder.Feed(mapPackets[index]);
        while (auto frame = decoder.Next())
        {
            frames.push_back(std::move(*frame));
        }
    }
    const bool restored = frames.size() == 3 && frames[0].Type() == map.Type() &&
                          frames[0].Payload() == map.Payload() &&
                          frames[1].Type() == control.Type() && frames[2].Type() == data.Type() &&
                          frames[2].Payload() == data.Payload();

    EXPECT_FALSE(partial.has_value());
    EXPECT_FALSE(interleavedControl.has_value());
    EXPECT_FALSE(interleavedData.has_value());
    EXPECT_TRUE(restored);
    EXPECT_EQ(decoder.BufferedBytes(), 0U);
}

TEST(Given_PacketEncoder, When_TcpSplitsEveryByte_Then_FramesArePreserved)
{
    PacketEncoder encoder;
    Decoder decoder;
    const Frame source(MessageType::ClientPacket, {1, 2, 3, 4});
    encoder.Queue(source.Encode());
    const auto packets = Drain(encoder);
    ASSERT_EQ(packets.size(), 1U);
    std::vector<Frame> decoded;

    for (const auto byte : packets.front())
    {
        decoder.Feed(&byte, 1);
        if (auto frame = decoder.Next())
        {
            decoded.push_back(std::move(*frame));
        }
    }
    const bool preserved = decoded.size() == 1 && decoded.front().Payload() == source.Payload();

    EXPECT_TRUE(preserved);
    EXPECT_EQ(decoder.BufferedBytes(), 0U);
}

TEST(Given_PacketEncoder, When_NextCallbackQueuesDuringPartialFrame_Then_RemainderPrecedesNewFrame)
{
    PacketEncoder encoder;
    Decoder decoder;
    const Frame source(MessageType::NetworkMap, std::vector<std::uint8_t>(3000, 'x'));
    encoder.Queue(source.Encode());
    const auto first = encoder.Next(VpnBufferCapacity);
    encoder.Queue(Frame(MessageType::Heartbeat, {}).Encode());
    auto packets = Drain(encoder);
    std::vector<Frame> decoded;

    decoder.Feed(first);
    const auto partial = decoder.Next();
    for (const auto& packet : packets)
    {
        decoder.Feed(packet);
        while (auto frame = decoder.Next())
        {
            decoded.push_back(std::move(*frame));
        }
    }
    const bool preserved = decoded.size() == 2 && decoded.front().Payload() == source.Payload() &&
                           decoded.back().Type() == MessageType::Heartbeat;

    EXPECT_FALSE(partial.has_value());
    EXPECT_TRUE(preserved);
    EXPECT_EQ(decoder.BufferedBytes(), 0U);
}

TEST(Given_PacketEncoder, When_MaximumFrameIsFragmented_Then_ReassemblyPreservesPayload)
{
    PacketEncoder encoder;
    Decoder decoder;
    const Frame source(MessageType::NetworkMap,
                       std::vector<std::uint8_t>(Frame::MaximumPayloadSize, 'x'));
    encoder.Queue(source.Encode());
    encoder.Queue(Frame(MessageType::Heartbeat, {}).Encode());
    const auto packets = Drain(encoder);
    std::vector<Frame> decoded;

    for (const auto& packet : packets)
    {
        decoder.Feed(packet);
        while (auto frame = decoder.Next())
        {
            decoded.push_back(std::move(*frame));
        }
    }
    const bool preserved = decoded.size() == 2 && decoded.front().Payload() == source.Payload() &&
                           decoded.back().Type() == MessageType::Heartbeat;

    EXPECT_TRUE(preserved);
    EXPECT_EQ(decoder.BufferedBytes(), 0U);
}

TEST(Given_PacketReassembler, When_FragmentHasNoData_Then_ItIsRejected)
{
    PacketReassembler decoder;
    const auto fragment = Fragment(0, 0);

    EXPECT_THROW(decoder.Accept(fragment), PacketFramingError);
}

TEST(Given_PacketReassembler, When_FragmentOverlapsFollowingRange_Then_ItIsRejected)
{
    PacketReassembler decoder;
    decoder.Accept(Fragment(8, 4));
    const auto fragment = Fragment(4, 5);

    EXPECT_THROW(decoder.Accept(fragment), PacketFramingError);
}

TEST(Given_PacketReassembler, When_FragmentOverlapsPrecedingRange_Then_ItIsRejected)
{
    PacketReassembler decoder;
    decoder.Accept(Fragment(4, 8));
    const auto fragment = Fragment(8, 8);

    EXPECT_THROW(decoder.Accept(fragment), PacketFramingError);
}

TEST(Given_PacketReassembler, When_DuplicateFragmentArrives_Then_ItIsRejected)
{
    PacketReassembler decoder;
    const auto fragment = Fragment(4, 8);
    decoder.Accept(fragment);

    EXPECT_THROW(decoder.Accept(fragment), PacketFramingError);
}

TEST(Given_PacketReassembler, When_DeliveredFragmentIsRepeated_Then_ItIsRejected)
{
    PacketReassembler decoder;
    const auto fragment = Fragment(0, 8);
    decoder.Accept(fragment);
    const auto delivered = decoder.Take();
    ASSERT_EQ(delivered.size(), 8U);

    EXPECT_THROW(decoder.Accept(fragment), PacketFramingError);
}

TEST(Given_PacketReassembler, When_FragmentExceedsWindow_Then_ItIsRejected)
{
    PacketReassembler decoder;
    const auto fragment = Fragment(PacketReassembler::MaximumWindow, 1);

    EXPECT_THROW(decoder.Accept(fragment), PacketFramingError);
}

TEST(Given_PacketReassembler, When_TooManyFragmentsWaitForGap_Then_ItIsRejected)
{
    PacketReassembler decoder;
    for (std::size_t index = 0; index < PacketReassembler::MaximumFragments; ++index)
    {
        decoder.Accept(Fragment(index + 1, 1));
    }
    const auto fragment = Fragment(PacketReassembler::MaximumFragments + 1, 1);

    EXPECT_THROW(decoder.Accept(fragment), PacketFramingError);
}

TEST(Given_PacketReassembler, When_FragmentsAreNested_Then_DecoderRejectsThem)
{
    PacketEncoder inner;
    PacketEncoder outer;
    Decoder decoder;
    inner.Queue(Frame(MessageType::Heartbeat, {}).Encode());
    outer.Queue(inner.Next(VpnBufferCapacity));
    decoder.Feed(outer.Next(VpnBufferCapacity));

    EXPECT_THROW((void)decoder.Next(), PacketFramingError);
}

TEST(Given_PacketReassembler, When_PlainFrameFollowsFragmentedStream_Then_DecoderRejectsIt)
{
    PacketEncoder encoder;
    Decoder decoder;
    encoder.Queue(Frame(MessageType::Heartbeat, {}).Encode());
    decoder.Feed(encoder.Next(VpnBufferCapacity));
    ASSERT_TRUE(decoder.Next().has_value());
    decoder.Feed(Frame(MessageType::Heartbeat, {}).Encode());

    EXPECT_THROW((void)decoder.Next(), PacketFramingError);
}

} // namespace
} // namespace tailgate::tests
