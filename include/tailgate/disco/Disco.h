#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include <tailgate/crypto/Crypto.h>

namespace tailgate::disco
{

class Disco
{
public:
    using TransactionId = std::array<std::uint8_t, 12>;

    // Tailscale reports DERP-received disco pings with this synthetic pong source address
    // (127.3.3.40) and the DERP region as the port; a zero source is discarded by peers.
    static constexpr std::uint32_t DerpMagicIpv4Address =
        (127U << 24U) | (3U << 16U) | (3U << 8U) | 40U;

    enum class MessageType
    {
        Ping,
        Pong,
        CallMeMaybe,
    };

    struct Endpoint
    {
        std::uint32_t Address = 0;
        std::uint16_t Port = 0;
    };

    struct Message
    {
        MessageType Type;
        TransactionId Transaction{};
        tailgate::crypto::Bytes32 Sender{};
        std::vector<Endpoint> Endpoints;
    };

    Disco(const tailgate::crypto::Bytes32& privateKey,
          const tailgate::crypto::Bytes32& nodePublicKey);

    [[nodiscard]] const tailgate::crypto::Bytes32& PublicKey() const;
    [[nodiscard]] TransactionId NewTransactionId() const;
    [[nodiscard]] std::vector<std::uint8_t> BuildPing(const tailgate::crypto::Bytes32& recipient,
                                                      const TransactionId& transaction) const;
    [[nodiscard]] std::vector<std::uint8_t> BuildPong(const tailgate::crypto::Bytes32& recipient,
                                                      const TransactionId& transaction,
                                                      std::uint32_t sourceAddress,
                                                      std::uint16_t sourcePort) const;
    [[nodiscard]] std::vector<std::uint8_t>
    BuildCallMeMaybe(const tailgate::crypto::Bytes32& recipient,
                     const std::vector<Endpoint>& endpoints) const;
    [[nodiscard]] std::optional<Message> Parse(const std::vector<std::uint8_t>& packet) const;
    [[nodiscard]] static bool IsDiscoPacket(const std::vector<std::uint8_t>& packet);

private:
    [[nodiscard]] std::vector<std::uint8_t> Seal(const tailgate::crypto::Bytes32& recipient,
                                                 const std::vector<std::uint8_t>& message) const;

    tailgate::crypto::Bytes32 Private{};
    tailgate::crypto::Bytes32 Public{};
    tailgate::crypto::Bytes32 NodePublic{};
};

} // namespace tailgate::disco
