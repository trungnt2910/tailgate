#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <stdexcept>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/ByteStream.h>
#include <tailgate/protocol/ControlHandshake.h>
#include <tailgate/protocol/Crypto.h>
#include <tailgate/protocol/NoiseTransport.h>

namespace
{

constexpr std::uint8_t NoiseTransportFrameType = 0x04;
constexpr std::size_t NoiseTransportFrameHeaderSize = 3;

class ReadCountingStream final : public tailgate::IByteStream
{
public:
    std::optional<std::size_t> TryWriteSome(const std::uint8_t*, std::size_t size) override
    {
        return size;
    }

    std::optional<std::vector<std::uint8_t>> TryReadSome(std::size_t maxBytes) override
    {
        ++ReadCount;
        if (Reads.empty())
        {
            return std::vector<std::uint8_t>{};
        }
        std::vector<std::uint8_t> result = std::move(Reads.front());
        Reads.pop_front();
        if (result.size() > maxBytes)
        {
            throw std::runtime_error("test read exceeds requested capacity");
        }
        return result;
    }

    std::size_t ReadCount = 0;
    std::deque<std::vector<std::uint8_t>> Reads;
};

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

TEST(Given_ProactiveNoiseFrame, When_CreatingTransport_Then_FramesRemainInNonceOrder)
{
    ReadCountingStream stream;
    tailgate::protocol::NoiseKeys keys;
    keys.RxKey[0] = 42;
    const std::vector<std::uint8_t> proactivePlaintext{1, 2, 3, 4};
    const std::vector<std::uint8_t> streamPlaintext{5, 6, 7, 8};
    stream.Reads.push_back(BuildTransportFrame(keys.RxKey, 1, streamPlaintext));
    tailgate::protocol::ControlHandshakeResult handshake{
        .Keys = keys,
        .ProactiveFrames = BuildTransportFrame(keys.RxKey, 0, proactivePlaintext),
    };
    tailgate::protocol::NoiseTransport transport(stream, std::move(handshake));

    const std::vector<std::uint8_t> proactiveReceived = transport.Receive();
    const std::size_t readsAfterProactive = stream.ReadCount;
    const std::vector<std::uint8_t> streamReceived = transport.Receive();

    EXPECT_EQ(proactiveReceived, proactivePlaintext);
    EXPECT_EQ(readsAfterProactive, 0U);
    EXPECT_EQ(streamReceived, streamPlaintext);
    EXPECT_EQ(stream.ReadCount, 1U);
}
