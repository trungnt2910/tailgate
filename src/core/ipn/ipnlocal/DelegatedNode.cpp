#include "tailgate/ipn/ipnlocal/DelegatedNode.h"

#include <algorithm>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <tailgate/base/Logger.h>
#include <tailgate/wgengine/wireguard/Tunnel.h>

namespace tailgate::ipn::ipnlocal
{
namespace
{

// The standard disco envelope starts with the six-byte magic followed by the sender key.
constexpr std::size_t DiscoMagicSize = 6;
constexpr std::size_t DiscoSenderSize = crypto::Bytes32{}.size();

} // namespace

DelegatedNode::DelegatedNode(wgengine::Session& session,
                             wgengine::Engine& engine,
                             wgengine::magicsock::Connection& udp,
                             DerpTransportFactory& derps,
                             base::TimeProvider& time)
    : m_session(session),
      m_engine(engine),
      m_udp(udp),
      m_derps(session, derps),
      m_delegation(m_derps, time),
      m_peers(std::ref(udp))
{
}

void DelegatedNode::Start(const types::netmap::NetworkConfig& network,
                          const wgengine::tstun::DeviceOptions& device)
{
    if (m_started)
    {
        throw std::logic_error("delegated node is already started");
    }
    if (!m_engine.OpenPacketDevice(device))
    {
        throw std::system_error(std::make_error_code(std::errc::device_or_resource_busy));
    }
    m_homeDerp = m_derps.Ensure(network.DerpRegion(), network.DerpHost(), true);
    UpdateNetwork(network);
    m_started = true;
}

void DelegatedNode::UpdateNetwork(const types::netmap::NetworkConfig& network)
{
    m_peers.Apply(network.Peers());
    m_derps.ApplyNetworkMap(network);
    m_delegation.ApplyMap(++m_mapRevision);
    m_controlOutput.push_back(hosted::EncodeMapAcknowledgement(m_mapRevision));
}

void DelegatedNode::HandleControl(const std::vector<std::uint8_t>& bytes)
{
    hosted::Decoder decoder;
    decoder.Feed(bytes);
    const auto frame = decoder.Next();
    if (!frame || decoder.Next())
    {
        throw std::system_error(std::make_error_code(std::errc::protocol_error));
    }
    switch (frame->Type())
    {
    case hosted::MessageType::NetworkMap:
        UpdateNetwork(hosted::ProtocolCodec::DecodeNetworkConfig(frame->Payload()));
        return;
    case hosted::MessageType::Delegation:
    {
        const auto request = hosted::DecodeDelegationRequest(*frame);
        if (!request)
        {
            throw std::system_error(std::make_error_code(std::errc::protocol_error));
        }
        m_delegation.Accept(*request);
        return;
    }
    case hosted::MessageType::PeerEndpoint:
    {
        const auto endpoint = hosted::ProtocolCodec::DecodePeerEndpoint(frame->Payload());
        if (auto* peer = m_peers.FindKey(endpoint.Peer()))
        {
            (void)m_udp.MarkDirect(peer->PublicKey, endpoint.Endpoint());
        }
        return;
    }
    default:
        throw std::system_error(std::make_error_code(std::errc::protocol_error));
    }
}

void DelegatedNode::HandleOutbound(const hosted::PeerPacket& packet)
{
    auto* peer = m_peers.FindKey(packet.Peer());
    if (!peer)
    {
        return;
    }
    using Priority = derp::DerpSendQueue::Priority;
    if (packet.Disco())
    {
        if (packet.EndpointAddress() != 0 && packet.EndpointPort() != 0)
        {
            (void)m_udp.SendDirect(
                peer->PublicKey,
                net::Endpoint(net::Ipv4Address::FromHostOrder(packet.EndpointAddress()),
                              packet.EndpointPort()),
                packet.Payload());
        }
        else if (packet.DerpIngressRoute())
        {
            if (auto* route = m_derps.ForRoute(*packet.DerpIngressRoute()))
            {
                route->Send(peer->PublicKey, packet.Payload(), Priority::Control);
            }
        }
        else
        {
            m_derps.ForRegion(peer->Config.DerpRegion())
                .Send(peer->PublicKey, packet.Payload(), Priority::Control);
            for (const auto& address : peer->Config.Endpoints())
            {
                if (const auto endpoint = net::Endpoint::TryParse(address))
                {
                    (void)m_udp.TrySendProbe(*endpoint, packet.Payload());
                }
            }
        }
        return;
    }
    peer->TxBytes += packet.Payload().size();
    if (m_udp.HasDirectPath(peer->PublicKey))
    {
        (void)m_udp.Send(peer->PublicKey, packet.Payload(), true);
    }
    else
    {
        m_derps.ForRegion(peer->Config.DerpRegion())
            .Send(peer->PublicKey,
                  packet.Payload(),
                  packet.Control() ? Priority::Control : Priority::Data);
    }
}

void DelegatedNode::Deliver(const crypto::Bytes32& peer,
                            const std::vector<std::uint8_t>& payload,
                            bool discoPacket,
                            const std::optional<net::Endpoint>& source,
                            std::optional<hosted::DerpRoute> route)
{
    const hosted::PeerPacket packet(peer,
                                    payload,
                                    false,
                                    discoPacket,
                                    source ? source->Address().HostOrder() : 0,
                                    source ? source->Port() : 0,
                                    std::move(route));
    const auto result = m_engine.WritePacket(hosted::ProtocolCodec::EncodePeerPacket(packet));
    if (result == wgengine::PacketWriteResult::Dropped ||
        result == wgengine::PacketWriteResult::Unavailable)
    {
        throw std::system_error(std::make_error_code(std::errc::no_buffer_space));
    }
}

wgengine::SessionWaitResult DelegatedNode::Wait(std::size_t maximumEvents,
                                                std::size_t maximumPackets,
                                                std::size_t maximumPacketSize)
{
    auto result = m_session.Wait(maximumEvents, maximumPackets, maximumPacketSize);
    m_delegation.Poll();
    if (!result.Failures.empty())
    {
        throw std::system_error(std::make_error_code(std::errc::network_down));
    }
    for (const auto& network : result.NetworkMaps)
    {
        UpdateNetwork(network);
    }
    for (const auto& bytes : result.Packets)
    {
        HandleOutbound(hosted::ProtocolCodec::DecodePeerPacket(bytes));
    }
    for (const auto& datagram : result.Datagrams)
    {
        const auto& bytes = datagram.Payload;
        if (disco::Disco::IsDiscoPacket(bytes))
        {
            if (bytes.size() < DiscoMagicSize + DiscoSenderSize)
            {
                continue;
            }
            crypto::Bytes32 key{};
            std::copy_n(bytes.begin() + DiscoMagicSize, key.size(), key.begin());
            if (auto* peer = m_peers.FindDiscoKey(key))
            {
                peer->RxBytes += bytes.size();
                Deliver(peer->PublicKey, bytes, true, datagram.Source, std::nullopt);
            }
        }
        else if (wgengine::wireguard::WireGuardTunnel::IsPacket(bytes))
        {
            // Roaming packets may have no confirmed source. Authentication belongs to the client.
            const auto peer = m_udp.AcceptDirectSource(datagram.Source);
            Deliver(peer.value_or(crypto::Bytes32{}), bytes, false, datagram.Source, std::nullopt);
        }
    }
    for (const auto& received : result.DerpPackets)
    {
        const auto& packet = received.Packet;
        auto* peer = m_peers.FindKey(packet.Source);
        if (!peer)
        {
            continue;
        }
        peer->RxBytes += packet.Payload.size();
        if (disco::Disco::IsDiscoPacket(packet.Payload))
        {
            if (packet.Payload.size() < DiscoMagicSize + DiscoSenderSize)
            {
                continue;
            }
            crypto::Bytes32 key{};
            std::copy_n(packet.Payload.begin() + DiscoMagicSize, key.size(), key.begin());
            auto* discoPeer = m_peers.FindDiscoKey(key);
            const auto& derps = m_derps.Entries();
            const auto route =
                std::ranges::find(derps, received.Connection, &DerpRuntime::Connection);
            if (discoPeer && route != derps.end())
            {
                Deliver(discoPeer->PublicKey, packet.Payload, true, std::nullopt, route->Route);
            }
        }
        else
        {
            Deliver(peer->PublicKey, packet.Payload, false, std::nullopt, std::nullopt);
        }
    }
    if (result.MaintenanceDue)
    {
        for (const auto& peer : m_peers.Entries())
        {
            (void)m_udp.ExpireDirectPath(peer.PublicKey);
        }
    }
    result.Packets.clear();
    result.Datagrams.clear();
    result.DerpPackets.clear();
    return result;
}

std::vector<hosted::Frame> DelegatedNode::TakeControlOutput()
{
    auto result = std::exchange(m_controlOutput, {});
    for (auto& frame : m_delegation.TakeOutput())
    {
        result.push_back(std::move(frame));
    }
    return result;
}

bool DelegatedNode::Connected() const
{
    return m_started &&
           m_session.DerpConnection(m_derps.Entries().at(m_homeDerp).Connection).Connected();
}

} // namespace tailgate::ipn::ipnlocal
