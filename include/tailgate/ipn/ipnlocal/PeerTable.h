#pragma once

#include <deque>
#include <functional>
#include <optional>

#include <tailgate/types/netmap/NetworkMap.h>
#include <tailgate/wgengine/magicsock/Connection.h>

namespace tailgate::ipn::ipnlocal
{

struct PeerRuntime
{
    types::netmap::PeerConfig Config;
    tailgate::crypto::Bytes32 PublicKey{};
    tailgate::crypto::Bytes32 DiscoPublicKey{};
    bool HasDiscoKey = false;
    std::uint64_t TxBytes = 0;
    std::uint64_t RxBytes = 0;
};

// Stable entries retain accounting while the current map controls routability.
// Delegated sessions own only encrypted paths; native WireGuard/disco stays in Session.
class PeerTable final
{
public:
    explicit PeerTable(std::optional<std::reference_wrapper<wgengine::magicsock::Connection>>
                           delegatedTransport = {});
    void Apply(const std::vector<types::netmap::PeerConfig>& configs);
    [[nodiscard]] std::deque<PeerRuntime>& Entries() noexcept;
    [[nodiscard]] const types::netmap::NetworkConfig& Network() const noexcept;
    [[nodiscard]] PeerRuntime* FindKey(const crypto::Bytes32& key);
    [[nodiscard]] PeerRuntime* FindDiscoKey(const crypto::Bytes32& key);

private:
    [[nodiscard]] std::optional<PeerRuntime> BuildPeer(const types::netmap::PeerConfig& config);
    static void UpdateDiscoKey(PeerRuntime& peer);
    const std::optional<std::reference_wrapper<wgengine::magicsock::Connection>>
        m_delegatedTransport;
    std::deque<PeerRuntime> m_peers;
    types::netmap::NetworkConfig m_network;
};

} // namespace tailgate::ipn::ipnlocal
