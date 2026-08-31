#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/net/Endpoint.h>

namespace tailgate::disco
{

class Disco
{
public:
    using TransactionId = std::array<std::uint8_t, 12>;

    // Tailscale reports DERP-received disco pings with this synthetic pong source address
    // (127.3.3.40) and the DERP region as the port; a zero source is discarded by peers.
    static constexpr tailgate::net::Ipv4Address DerpMagicIpv4Address =
        tailgate::net::Ipv4Address::FromOctets(127, 3, 3, 40);

    enum class MessageType
    {
        Ping,
        Pong,
        CallMeMaybe,
    };

    struct Message
    {
        MessageType Type;
        TransactionId Transaction{};
        tailgate::crypto::Bytes32 Sender{};
        std::optional<tailgate::net::Endpoint> SourceEndpoint;
        std::vector<tailgate::net::Endpoint> Endpoints;
    };

    Disco(const tailgate::crypto::Bytes32& privateKey,
          const tailgate::crypto::Bytes32& nodePublicKey);

    [[nodiscard]] const tailgate::crypto::Bytes32& PublicKey() const;
    [[nodiscard]] TransactionId NewTransactionId() const;
    [[nodiscard]] std::vector<std::uint8_t> BuildPing(const tailgate::crypto::Bytes32& recipient,
                                                      const TransactionId& transaction) const;
    [[nodiscard]] std::vector<std::uint8_t> BuildPong(const tailgate::crypto::Bytes32& recipient,
                                                      const TransactionId& transaction,
                                                      tailgate::net::Ipv4Address sourceAddress,
                                                      std::uint16_t sourcePort) const;
    [[nodiscard]] std::vector<std::uint8_t>
    BuildCallMeMaybe(const tailgate::crypto::Bytes32& recipient,
                     const std::vector<tailgate::net::Endpoint>& endpoints) const;
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
