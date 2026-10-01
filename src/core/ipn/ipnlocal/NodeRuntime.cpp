#include "tailgate/ipn/ipnlocal/NodeRuntime.h"

#include <utility>

#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/net/packet/Tsmp.h>

namespace tailgate::ipn::ipnlocal
{

NodeRuntime::NodeRuntime(LocalServices& services, DnsForwarder& dns, wgengine::ping::Tracker& pings)
    : m_dispatch(services), m_dns(dns), m_pings(pings)
{
}

void NodeRuntime::SetNetworkConfig(const types::netmap::NetworkConfig& config)
{
    m_dispatch.SetNetworkConfig(config);
    m_network = config;
}

void NodeRuntime::SetPeerApiPort(std::optional<std::uint16_t> port) noexcept
{
    m_peerApiPort = port;
}

void NodeRuntime::HandleHostPacket(const std::vector<std::uint8_t>& packet,
                                   const PacketDelivery& delivery)
{
    if (const auto query = net::packet::Ipv4UdpDatagram::Parse(packet);
        query && query->Destination() == net::dns::MagicDnsIpv4Address &&
        query->DestinationPort() == net::dns::DnsPort)
    {
        const auto self = net::Ipv4Address::TryParse(m_network.SelfAddress());
        if (self && query->Source() == self->HostOrder())
        {
            if (auto response = net::dns::TailnetDnsResponse::Build(m_network, packet))
            {
                (void)delivery.Host(std::move(*response));
            }
        }
        return;
    }
    if (!m_dispatch.HandleHostPacket(packet))
    {
        // IPv4 and IPv6 routing both belong to the shared WireGuard router.
        delivery.Network(packet);
    }
}

NodeReceiveResult NodeRuntime::HandlePeerPacket(const crypto::Bytes32& peer,
                                                std::vector<std::uint8_t> packet,
                                                base::TimeProvider::TimePoint now,
                                                const PacketDelivery& delivery)
{
    NodeReceiveResult result;
    if (m_dispatch.HandlePeerPacket(peer, packet))
    {
        return result;
    }
    if (m_peerApiPort)
    {
        if (const auto pong = net::packet::TsmpPacket::BuildPong(packet, *m_peerApiPort))
        {
            delivery.Peer(peer, *pong);
            return result;
        }
    }
    if (const auto pong = net::packet::TsmpPacket::ParsePong(packet))
    {
        result.Ping = m_pings.CompleteTsmp(pong->Token(), pong->PeerApiPort(), now);
        return result;
    }
    result.Dns = m_dns.CompletePacket(packet);
    if (!result.Dns)
    {
        result.HostAvailable = delivery.Host(std::move(packet));
    }
    return result;
}

void NodeRuntime::Poll(std::size_t maximumPackets, const PacketDelivery& delivery)
{
    m_dispatch.Poll(maximumPackets, delivery);
}

std::optional<base::TimeProvider::TimePoint> NodeRuntime::NextDeadline() const
{
    auto deadline = m_dispatch.NextDeadline();
    for (const auto candidate : {m_dns.NextDeadline(), m_pings.NextDeadline()})
    {
        if (candidate && (!deadline || *candidate < *deadline))
        {
            deadline = candidate;
        }
    }
    return deadline;
}

} // namespace tailgate::ipn::ipnlocal
