#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::wgengine::wireguard
{

class WireGuardRouter final
{
public:
    struct TransportPacket
    {
        tailgate::crypto::Bytes32 Peer{};
        std::vector<std::uint8_t> Payload;
        bool Control = false;
        bool ExpectResponse = true;
        bool Handshake = false;
    };

    struct ReceiveResult
    {
        tailgate::crypto::Bytes32 Source{};
        std::vector<TransportPacket> Outbound;
        std::vector<std::vector<std::uint8_t>> Plaintext;
        bool SessionEstablished = false;
        bool Accepted = false;
    };

    WireGuardRouter(const tailgate::crypto::Bytes32& nodePrivateKey,
                    const std::vector<tailgate::types::netmap::PeerConfig>& peers,
                    std::string exitNode = {});
    ~WireGuardRouter();
    WireGuardRouter(WireGuardRouter&&) noexcept;
    WireGuardRouter& operator=(WireGuardRouter&&) noexcept;
    WireGuardRouter(const WireGuardRouter&) = delete;
    WireGuardRouter& operator=(const WireGuardRouter&) = delete;

    void UpdatePeers(const std::vector<tailgate::types::netmap::PeerConfig>& peers,
                     std::string exitNode = {});
    [[nodiscard]] std::vector<TransportPacket> Send(const std::vector<std::uint8_t>& plaintext);
    [[nodiscard]] std::vector<TransportPacket> SendTo(const tailgate::crypto::Bytes32& peer,
                                                      const std::vector<std::uint8_t>& plaintext);
    [[nodiscard]] std::vector<TransportPacket> Start(const tailgate::crypto::Bytes32& peer);
    [[nodiscard]] ReceiveResult Receive(const tailgate::crypto::Bytes32& source,
                                        const std::vector<std::uint8_t>& packet);
    [[nodiscard]] ReceiveResult Receive(const std::vector<std::uint8_t>& packet);
    [[nodiscard]] std::vector<TransportPacket> UpdateTimers();
    [[nodiscard]] bool HasSession(const tailgate::crypto::Bytes32& peer) const;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace tailgate::wgengine::wireguard
