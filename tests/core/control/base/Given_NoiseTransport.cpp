#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/protocol/ControlHandshake.h>
#include <tailgate/protocol/Crypto.h>
#include <tailgate/protocol/NoiseTransport.h>

#include "support/ScriptedByteStream.h"

namespace
{

constexpr std::uint8_t NoiseTransportFrameType = 0x04;
constexpr std::size_t NoiseTransportFrameHeaderSize = 3;
constexpr std::size_t MaximumNoiseCiphertextSize = 0xffff;

std::vector<std::uint8_t> BuildTransportFrame(const tailgate::protocol::Bytes32& key,
                                              std::uint64_t nonce,
                                              const std::vector<std::uint8_t>& plaintext)
{
    const std::vector<std::uint8_t> ciphertext =
        tailgate::protocol::ChaCha20Poly1305EncryptBigNonce(key, nonce, {}, plaintext);
    std::vector<std::uint8_t> frame;
    frame.reserve(NoiseTransportFrameHeaderSize + ciphertext.size());
    frame.push_back(NoiseTransportFrameType);
    frame.push_back(static_cast<std::uint8_t>(ciphertext.size() >> 8U));
    frame.push_back(static_cast<std::uint8_t>(ciphertext.size()));
    frame.insert(frame.end(), ciphertext.begin(), ciphertext.end());
    return frame;
}

} // namespace

TEST(Given_NoiseTransport, When_ProactiveFramePrecedesStreamData_Then_NonceOrderIsPreserved)
{
    tailgate::test::ScriptedByteStream stream;
    tailgate::protocol::NoiseKeys keys;
    keys.RxKey[0] = 42;
    const std::vector<std::uint8_t> proactivePlaintext{1, 2, 3, 4};
    const std::vector<std::uint8_t> streamPlaintext{5, 6, 7, 8};
    stream.QueueRead(BuildTransportFrame(keys.RxKey, 1, streamPlaintext));
    tailgate::protocol::ControlHandshakeResult handshake{
        .Keys = keys,
        .ProactiveFrames = BuildTransportFrame(keys.RxKey, 0, proactivePlaintext),
    };
    tailgate::protocol::NoiseTransport transport(stream, std::move(handshake));

    const std::vector<std::uint8_t> proactiveReceived = transport.Receive();
    const std::size_t readsAfterProactive = stream.ReadCalls;
    const std::vector<std::uint8_t> streamReceived = transport.Receive();

    EXPECT_EQ(proactiveReceived, proactivePlaintext);
    EXPECT_EQ(readsAfterProactive, 0U);
    EXPECT_EQ(streamReceived, streamPlaintext);
    EXPECT_EQ(stream.ReadCalls, 1U);
}

TEST(Given_NoiseTransport, When_FrameIsFragmented_Then_TryReceiveWaitsForCompletion)
{
    tailgate::test::ScriptedByteStream stream;
    tailgate::protocol::NoiseKeys keys;
    keys.RxKey[0] = 42;
    const std::vector<std::uint8_t> plaintext{1, 2, 3, 4};
    const std::vector<std::uint8_t> frame = BuildTransportFrame(keys.RxKey, 0, plaintext);
    stream.QueueRead({frame.begin(), frame.begin() + 2});
    stream.QueueRead({frame.begin() + 2, frame.end()});
    tailgate::protocol::NoiseTransport transport(stream, keys);

    const std::optional<std::vector<std::uint8_t>> partial = transport.TryReceive();
    const std::optional<std::vector<std::uint8_t>> complete = transport.TryReceive();

    EXPECT_FALSE(partial.has_value());
    EXPECT_TRUE(complete.has_value());
    EXPECT_EQ(complete.value(), plaintext);
}

TEST(Given_NoiseTransport, When_FramesAreCoalesced_Then_SecondFrameUsesBufferedInput)
{
    tailgate::test::ScriptedByteStream stream;
    tailgate::protocol::NoiseKeys keys;
    keys.RxKey[0] = 42;
    const std::vector<std::uint8_t> firstPlaintext{1, 2};
    const std::vector<std::uint8_t> secondPlaintext{3, 4};
    std::vector<std::uint8_t> input = BuildTransportFrame(keys.RxKey, 0, firstPlaintext);
    const std::vector<std::uint8_t> secondFrame =
        BuildTransportFrame(keys.RxKey, 1, secondPlaintext);
    input.insert(input.end(), secondFrame.begin(), secondFrame.end());
    stream.QueueRead(std::move(input));
    tailgate::protocol::NoiseTransport transport(stream, keys);

    const std::optional<std::vector<std::uint8_t>> first = transport.TryReceive();
    const std::size_t readsAfterFirst = stream.ReadCalls;
    const std::optional<std::vector<std::uint8_t>> second = transport.TryReceive();

    EXPECT_TRUE(first.has_value());
    EXPECT_TRUE(second.has_value());
    EXPECT_EQ(first.value(), firstPlaintext);
    EXPECT_EQ(second.value(), secondPlaintext);
    EXPECT_EQ(stream.ReadCalls, readsAfterFirst);
}

TEST(Given_NoiseTransport, When_WriteWouldBlock_Then_FlushResumesEncryptedFrame)
{
    tailgate::test::ScriptedByteStream stream;
    stream.BlockedWrites = 1;
    tailgate::protocol::NoiseKeys keys;
    keys.TxKey[0] = 42;
    const std::vector<std::uint8_t> plaintext{1, 2, 3, 4};
    const std::vector<std::uint8_t> expected = BuildTransportFrame(keys.TxKey, 0, plaintext);
    tailgate::protocol::NoiseTransport transport(stream, keys);

    transport.Send(plaintext);
    const bool pendingBeforeFlush = transport.HasPendingOutput();
    transport.Flush();

    EXPECT_TRUE(pendingBeforeFlush);
    EXPECT_FALSE(transport.HasPendingOutput());
    EXPECT_EQ(stream.Written, expected);
}

TEST(Given_NoiseTransport, When_FrameTypeIsUnexpected_Then_ReceiveRejectsIt)
{
    tailgate::test::ScriptedByteStream stream;
    stream.QueueRead({0xff, 0, 0});
    tailgate::protocol::NoiseKeys keys;
    tailgate::protocol::NoiseTransport transport(stream, keys);
    const auto receive = [&]()
    {
        (void)transport.TryReceive();
    };

    EXPECT_THROW(receive(), std::runtime_error);
}

TEST(Given_NoiseTransport, When_PlaintextExceedsFrameLimit_Then_SendRejectsIt)
{
    tailgate::test::ScriptedByteStream stream;
    tailgate::protocol::NoiseKeys keys;
    tailgate::protocol::NoiseTransport transport(stream, keys);
    const std::vector<std::uint8_t> oversized(MaximumNoiseCiphertextSize);
    const auto send = [&]()
    {
        transport.Send(oversized);
    };

    EXPECT_THROW(send(), std::runtime_error);
    EXPECT_TRUE(stream.Written.empty());
}
