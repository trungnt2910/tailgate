#pragma once

#include <optional>

#include <tailgate/ipn/ipnlocal/DnsForwarder.h>
#include <tailgate/ipn/ipnlocal/PacketDispatch.h>
#include <tailgate/wgengine/ping/Tracker.h>

namespace tailgate::ipn::ipnlocal
{

struct NodeReceiveResult
{
    bool HostAvailable = true;
    std::optional<DnsReply> Dns;
    std::optional<wgengine::ping::Result> Ping;
    std::optional<net::Endpoint> DirectSource;
};

// Serialized plaintext processing for one node, independent of its outer transport.
// Delivery is supplied per operation: replacing a path must not replace this runtime
// or its local services, pending resolver requests, or ping tracker.
class NodeRuntime final
{
public:
    NodeRuntime(LocalServices& services, DnsForwarder& dns, wgengine::ping::Tracker& pings);

    void SetNetworkConfig(const types::netmap::NetworkConfig& config);
    void SetPeerApiPort(std::optional<std::uint16_t> port) noexcept;
    void HandleHostPacket(const std::vector<std::uint8_t>& packet, const PacketDelivery& delivery);
    // The caller supplies the peer authenticated by WireGuard, never a relay envelope key.
    [[nodiscard]] NodeReceiveResult HandlePeerPacket(const crypto::Bytes32& peer,
                                                     std::vector<std::uint8_t> packet,
                                                     base::TimeProvider::TimePoint now,
                                                     const PacketDelivery& delivery);
    void Poll(std::size_t maximumPackets, const PacketDelivery& delivery);
    [[nodiscard]] std::optional<base::TimeProvider::TimePoint> NextDeadline() const;

private:
    PacketDispatch m_dispatch;
    types::netmap::NetworkConfig m_network;
    DnsForwarder& m_dns;
    wgengine::ping::Tracker& m_pings;
    std::optional<std::uint16_t> m_peerApiPort = 0;
};

} // namespace tailgate::ipn::ipnlocal
