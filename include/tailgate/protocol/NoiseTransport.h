#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include <tailgate/ByteStream.h>
#include <tailgate/protocol/ControlHandshake.h>

namespace tailgate::protocol
{

class NoiseTransport
{
public:
    NoiseTransport(IByteStream& stream, NoiseKeys keys);
    NoiseTransport(IByteStream& stream, ControlHandshakeResult handshake);

    void Send(const std::vector<std::uint8_t>& plaintext);
    void Flush();
    [[nodiscard]] bool HasPendingOutput() const;
    [[nodiscard]] std::vector<std::uint8_t> Receive();
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> TryReceive();

private:
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> TryTakeBufferedFrame();

    IByteStream& m_stream;
    NoiseKeys m_keys;
    std::uint64_t m_txNonce = 0;
    std::uint64_t m_rxNonce = 0;
    std::vector<std::uint8_t> m_receiveBuffer;
    std::vector<std::uint8_t> m_sendBuffer;
    std::size_t m_sendOffset = 0;
};

} // namespace tailgate::protocol
