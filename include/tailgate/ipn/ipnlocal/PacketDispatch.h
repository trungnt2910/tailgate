#pragma once

#include <functional>

#include <tailgate/ipn/ipnlocal/LocalServices.h>

namespace tailgate::ipn::ipnlocal
{

struct PacketDelivery
{
    // False stops delivery after a terminal host-device failure.
    std::function<bool(std::vector<std::uint8_t>)> Host;
    std::function<void(const std::vector<std::uint8_t>&)> Network;
    std::function<void(const crypto::Bytes32&, const std::vector<std::uint8_t>&)> Peer;
};

class PacketDispatch final
{
public:
    explicit PacketDispatch(LocalServices& services);
    void SetNetworkConfig(const types::netmap::NetworkConfig& config);
    [[nodiscard]] bool HandleHostPacket(const std::vector<std::uint8_t>& packet);
    [[nodiscard]] bool HandlePeerPacket(const crypto::Bytes32& peer,
                                        const std::vector<std::uint8_t>& packet);
    void Poll(std::size_t maximumPackets, const PacketDelivery& delivery);
    [[nodiscard]] std::optional<base::TimeProvider::TimePoint> NextDeadline() const;

private:
    LocalServices& m_services;
};

} // namespace tailgate::ipn::ipnlocal
