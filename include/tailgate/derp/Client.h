#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

#include <tailgate/base/ByteStream.h>

namespace tailgate::derp
{

class DerpClient
{
public:
    using Key = std::array<std::uint8_t, 32>;
    using Authenticator = std::function<std::vector<std::uint8_t>(const Key& serverKey)>;

    struct Packet
    {
        Key Source;
        std::vector<std::uint8_t> Payload;
    };

    DerpClient(tailgate::base::IByteStream& stream, Key privateKey, Key publicKey);
    DerpClient(tailgate::base::IByteStream& stream, Authenticator authenticator);
    [[nodiscard]] static std::vector<std::uint8_t>
    BuildClientInfo(const Key& privateKey, const Key& publicKey, const Key& serverKey);
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

    tailgate::base::IByteStream& Stream;
    Key PrivateKey;
    Key PublicKey;
    Key ServerKey{};
    Authenticator Authenticate;
    std::vector<std::uint8_t> ReceiveBuffer;
    std::vector<std::uint8_t> SendBuffer;
    std::size_t SendOffset = 0;
};

} // namespace tailgate::derp
