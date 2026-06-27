#pragma once

#include "tailgate/ByteStream.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tailgate::protocol
{

class DerpClient
{
public:
    using Key = std::array<std::uint8_t, 32>;

    struct Packet
    {
        Key Source;
        std::vector<std::uint8_t> Payload;
    };

    DerpClient(IByteStream& stream, Key privateKey, Key publicKey);
    void Connect(const std::string& hostname);
    void Send(const Key& destination, const std::vector<std::uint8_t>& packet);
    [[nodiscard]] Packet Receive();
    [[nodiscard]] std::optional<Packet> ReceiveAvailable();
    [[nodiscard]] std::vector<Packet> ReceiveAvailableBatch();
    [[nodiscard]] bool HasBufferedInput() const;
    void SetPreferred(bool preferred);
    void Flush();
    [[nodiscard]] bool HasPendingOutput() const;

private:
    struct Frame
    {
        std::uint8_t Type;
        std::vector<std::uint8_t> Payload;
    };

    void WriteFrame(std::uint8_t type, const std::vector<std::uint8_t>& payload);
    [[nodiscard]] Frame ReadFrame();

    IByteStream& Stream;
    Key PrivateKey;
    Key PublicKey;
    Key ServerKey{};
    std::vector<std::uint8_t> ReceiveBuffer;
    std::vector<std::uint8_t> SendBuffer;
    std::size_t SendOffset = 0;
};

} // namespace tailgate::protocol
