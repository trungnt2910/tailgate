#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

namespace tailgate::protocol
{

class WireGuardTunnel
{
public:
    using Key = std::array<std::uint8_t, 32>;
    using PeerId = std::size_t;

    enum class TimerAction
    {
        None,
        SendHandshake,
        SendKeepalive,
    };

    struct ReceivedPacket
    {
        PeerId Peer;
        std::vector<std::uint8_t> Plaintext;
        std::vector<std::uint8_t> Reply;
        bool SessionEstablished;
    };

    explicit WireGuardTunnel(const Key& privateKey);
    ~WireGuardTunnel();
    WireGuardTunnel(WireGuardTunnel&&) noexcept;
    WireGuardTunnel& operator=(WireGuardTunnel&&) noexcept;
    WireGuardTunnel(const WireGuardTunnel&) = delete;
    WireGuardTunnel& operator=(const WireGuardTunnel&) = delete;

    PeerId AddPeer(const Key& publicKey,
                   const Key& presharedKey = {},
                   std::uint16_t keepalive = 10,
                   bool initiateAutomatically = false);
    [[nodiscard]] std::vector<std::uint8_t> CreateHandshake(PeerId peer);
    [[nodiscard]] std::optional<ReceivedPacket>
    ProcessPacket(PeerId peer, const std::vector<std::uint8_t>& packet);
    [[nodiscard]] std::optional<ReceivedPacket>
    ProcessPacket(const std::vector<std::uint8_t>& packet);
    [[nodiscard]] std::vector<std::uint8_t> Encrypt(PeerId peer,
                                                    const std::vector<std::uint8_t>& plaintext);
    [[nodiscard]] TimerAction UpdateTimers(PeerId peer);
    [[nodiscard]] bool HasSession(PeerId peer) const;

private:
    class Impl;
    std::unique_ptr<Impl> Implementation;
};

} // namespace tailgate::protocol
