#pragma once

#include "tailgate/control/NetworkMap.h"
#include "tailgate/protocol/Crypto.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace tailgate::protocol
{

class WireGuardRouter final
{
public:
    struct TransportPacket
    {
        Bytes32 Peer{};
        std::vector<std::uint8_t> Payload;
        bool Control = false;
    };

    struct ReceiveResult
    {
        std::vector<TransportPacket> Outbound;
        std::vector<std::vector<std::uint8_t>> Plaintext;
    };

    WireGuardRouter(const Bytes32& nodePrivateKey,
                    const std::vector<control::PeerConfig>& peers,
                    std::string exitNode = {});
    ~WireGuardRouter();
    WireGuardRouter(WireGuardRouter&&) noexcept;
    WireGuardRouter& operator=(WireGuardRouter&&) noexcept;
    WireGuardRouter(const WireGuardRouter&) = delete;
    WireGuardRouter& operator=(const WireGuardRouter&) = delete;

    void UpdatePeers(const std::vector<control::PeerConfig>& peers, std::string exitNode = {});
    [[nodiscard]] std::vector<TransportPacket> Send(const std::vector<std::uint8_t>& plaintext);
    [[nodiscard]] ReceiveResult Receive(const Bytes32& source,
                                        const std::vector<std::uint8_t>& packet);
    [[nodiscard]] std::vector<TransportPacket> UpdateTimers();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace tailgate::protocol
