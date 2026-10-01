#include "tailgate/ipn/ipnlocal/PacketDispatch.h"

#include <utility>

namespace tailgate::ipn::ipnlocal
{

PacketDispatch::PacketDispatch(LocalServices& services) : m_services(services)
{
}

void PacketDispatch::SetNetworkConfig(const types::netmap::NetworkConfig& config)
{
    m_services.SetNetworkConfig(config);
}

bool PacketDispatch::HandleHostPacket(const std::vector<std::uint8_t>& packet)
{
    return m_services.HandleHostPacket(packet);
}

bool PacketDispatch::HandlePeerPacket(const crypto::Bytes32& peer,
                                      const std::vector<std::uint8_t>& packet)
{
    return m_services.HandlePeerPacket(peer, packet);
}

void PacketDispatch::Poll(std::size_t maximumPackets, const PacketDelivery& delivery)
{
    m_services.Poll();
    for (auto& packet : m_services.TakeOutput(maximumPackets))
    {
        if (packet.ForwardFromHost)
        {
            delivery.Network(packet.Bytes);
        }
        else if (packet.Peer)
        {
            delivery.Peer(*packet.Peer, packet.Bytes);
        }
        else
        {
            if (!delivery.Host(std::move(packet.Bytes)))
            {
                break;
            }
        }
    }
}

std::optional<base::TimeProvider::TimePoint> PacketDispatch::NextDeadline() const
{
    return m_services.NextDeadline();
}

} // namespace tailgate::ipn::ipnlocal
