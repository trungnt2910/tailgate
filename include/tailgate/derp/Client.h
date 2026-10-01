#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <stop_token>
#include <string>
#include <vector>

#include <tailgate/base/ByteStream.h>

namespace tailgate::derp
{

class Authenticator
{
public:
    virtual ~Authenticator() = default;
    [[nodiscard]] virtual std::vector<std::uint8_t>
    Authenticate(const std::array<std::uint8_t, 32>& serverKey, std::stop_token cancellation) = 0;
};

class DerpClient
{
public:
    using Key = std::array<std::uint8_t, 32>;

    struct Packet
    {
        Key Source;
        std::vector<std::uint8_t> Payload;
    };

    DerpClient(tailgate::base::ByteStream& stream, Key privateKey, Key publicKey);
    DerpClient(tailgate::base::ByteStream& stream, Authenticator& authenticator);
    [[nodiscard]] static std::vector<std::uint8_t>
    BuildClientInfo(const Key& privateKey, const Key& publicKey, const Key& serverKey);
    void Connect(const std::string& hostname, std::stop_token cancellation = {});
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

    void WriteFrame(std::uint8_t type,
                    std::span<const std::uint8_t> payload,
                    std::span<const std::uint8_t> prefix = {});
    [[nodiscard]] Frame ReadFrame();

    tailgate::base::ByteStream& Stream;
    Key PrivateKey;
    Key PublicKey;
    Key ServerKey{};
    std::optional<std::reference_wrapper<Authenticator>> m_authenticator;
    std::vector<std::uint8_t> ReceiveBuffer;
    std::vector<std::uint8_t> SendBuffer;
    std::size_t SendOffset = 0;
};

} // namespace tailgate::derp
