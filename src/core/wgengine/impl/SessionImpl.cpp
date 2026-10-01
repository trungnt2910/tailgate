#include "SessionImpl.h"

#include <algorithm>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <utility>

#include <tailgate/base/Logger.h>
#include <tailgate/crypto/PrefixedKey.h>
#include <tailgate/disco/Disco.h>
#include <tailgate/net/stun/Stun.h>

namespace tailgate::wgengine::impl
{

SessionImpl::SessionImpl(tailgate::wgengine::Engine& engine,
                         tailgate::base::TimeProvider& timeProvider,
                         tailgate::crypto::Random& random,
                         tailgate::wgengine::magicsock::Connection& connection,
                         PeerProtocol& protocol) noexcept
    : m_engine(engine),
      m_timeProvider(timeProvider),
      m_random(random),
      m_connection(connection),
      m_protocol(protocol),
      m_nextMaintenance(m_timeProvider.Now() + MaintenanceInterval)
{
}

void SessionImpl::Reset() noexcept
{
    m_packetPath.reset();
    m_discovery.reset();
    m_control.reset();
    m_derps.clear();
    m_peers.clear();
    m_configured = false;
    m_advertisedEndpoint = {};
    m_homeDerpRegion = 0;
    m_nextMaintenance = m_timeProvider.Now() + MaintenanceInterval;
    m_engine.Reset();
}

void SessionImpl::SetControlConnection(
    std::unique_ptr<tailgate::control::client::Connection> connection)
{
    if (m_control || !connection)
    {
        throw std::invalid_argument("The session control connection must be set exactly once.");
    }
    m_control = std::move(connection);
}

tailgate::control::client::Connection* SessionImpl::ControlConnection() noexcept
{
    return m_control.get();
}

tailgate::wgengine::DerpConnectionId
SessionImpl::AddDerpConnection(int region, std::unique_ptr<tailgate::derp::Connection> connection)
{
    if (region == 0 || !connection)
    {
        throw std::invalid_argument("The DERP connection is required.");
    }
    const tailgate::wgengine::DerpConnectionId result = m_derps.size();
    m_derps.push_back(DerpState{
        .Region = region,
        .Connection = std::move(connection),
    });
    return result;
}

tailgate::derp::Connection&
SessionImpl::DerpConnection(tailgate::wgengine::DerpConnectionId connection)
{
    if (connection >= m_derps.size())
    {
        throw std::out_of_range("The DERP connection does not exist.");
    }
    return *m_derps[connection].Connection;
}

std::size_t SessionImpl::DerpConnectionCount() const noexcept
{
    return m_derps.size();
}

std::optional<tailgate::net::Endpoint>
SessionImpl::DiscoverEndpoint(const tailgate::net::Endpoint& server,
                              std::chrono::milliseconds timeout)
{
    StartEndpointDiscovery(server, timeout);
    while (true)
    {
        auto ready = Wait(StunMaximumEvents, StunMaximumDatagrams, StunMaximumDatagramSize);
        if (ready.EndpointDiscovery)
        {
            return ready.EndpointDiscovery->Endpoint;
        }
    }
}

tailgate::wgengine::SessionWaitResult
SessionImpl::Wait(std::size_t maximumEvents,
                  std::size_t maximumPacketsPerSource,
                  std::size_t maximumPacketSize,
                  std::optional<base::TimeProvider::TimePoint> deadline)
{
    SessionWaitResult discovery;
    PollEndpointDiscovery(discovery);
    auto next = deadline ? std::min(*deadline, m_nextMaintenance) : m_nextMaintenance;
    if (m_discovery)
    {
        next = std::min(next, std::min(m_discovery->Deadline, m_discovery->NextSend));
    }
    if (discovery.EndpointDiscovery)
    {
        next = m_timeProvider.Now();
    }
    std::unique_ptr<tailgate::base::WaitToken> maintenance = m_timeProvider.At(next);
    tailgate::wgengine::EngineWaitResult engineResult =
        m_engine.Wait(*maintenance, maximumEvents, maximumPacketsPerSource, maximumPacketSize);
    tailgate::wgengine::SessionWaitResult result{
        .Status = engineResult.Status,
        .Datagrams = {},
        .Packets = {},
        .Failures = {},
        .NetworkMaps = {},
        .DerpPackets = {},
        .WireGuardEvents = {},
        .DiscoEvents = {},
        .PathEvents = {},
        .PlatformEvents = {},
        .MaintenanceDue = false,
        .EndpointDiscovery = std::move(discovery.EndpointDiscovery),
    };
    ProcessProtocolEvents(std::move(engineResult), result);
    PollEndpointDiscovery(result);
    if (m_timeProvider.Now() >= m_nextMaintenance)
    {
        Maintain(result);
    }
    else if (result.Status == tailgate::base::EventWaitStatus::Woken)
    {
        MaintainConnections(result);
    }
    // A completion wake can carry packets, configuration or due timers. Only an
    // empty wake is skippable by callers; otherwise expose the work as events.
    if (result.Status == base::EventWaitStatus::Woken &&
        (result.MaintenanceDue || !result.Datagrams.empty() || !result.Packets.empty() ||
         !result.Failures.empty() || !result.NetworkMaps.empty() || !result.DerpPackets.empty() ||
         !result.WireGuardEvents.empty() || !result.DiscoEvents.empty() ||
         !result.PathEvents.empty() || !result.PlatformEvents.empty() || result.EndpointDiscovery))
    {
        result.Status = base::EventWaitStatus::Events;
    }
    return result;
}

void SessionImpl::Configure(tailgate::wgengine::SessionOptions options)
{
    if (m_configured)
    {
        throw std::logic_error("The WireGuard session is already configured.");
    }
    const std::string exitNode = options.ExitNode;
    m_protocol.Initialize(
        PeerIdentity{
            .NodePrivateKey = options.NodePrivateKey,
            .NodePublicKey = options.NodePublicKey,
            .DiscoPrivateKey = options.DiscoPrivateKey,
        },
        options.Peers,
        exitNode);
    m_configured = true;
    m_advertisedEndpoint = options.AdvertisedEndpoint;
    m_homeDerpRegion = options.HomeDerpRegion;
    UpdatePeers(options.Peers, exitNode);
}

void SessionImpl::UpdatePeers(const std::vector<tailgate::types::netmap::PeerConfig>& peers,
                              std::string exitNode)
{
    if (m_configured)
    {
        m_protocol.Router().UpdatePeers(peers, std::move(exitNode));
    }
    for (PeerState& peer : m_peers)
    {
        peer.Active = false;
    }
    for (const tailgate::types::netmap::PeerConfig& config : peers)
    {
        const std::optional<tailgate::crypto::Bytes32> publicKey =
            tailgate::crypto::PrefixedKey::TryParse(config.Key(), "nodekey:");
        if (!publicKey)
        {
            continue;
        }
        const auto existing = std::find_if(m_peers.begin(),
                                           m_peers.end(),
                                           [&](const PeerState& state)
                                           {
                                               return state.PublicKey == *publicKey;
                                           });
        PeerState* peer = existing == m_peers.end() ? nullptr : &*existing;
        if (peer == nullptr)
        {
            m_peers.push_back(PeerState{
                .Config = config,
                .PublicKey = *publicKey,
                .DiscoKey = std::nullopt,
                .Endpoints = {},
                .TransmittedBytes = 0,
                .ReceivedBytes = 0,
                .Active = true,
            });
            peer = &m_peers.back();
            (void)m_connection.AddPeer(*publicKey);
        }
        else if (!peer->Active)
        {
            (void)m_connection.AddPeer(*publicKey);
        }
        const bool identityChanged = peer->Config.DiscoKey() != config.DiscoKey();
        const bool endpointsChanged = peer->Config.Endpoints() != config.Endpoints();
        peer->Config = config;
        peer->DiscoKey = tailgate::crypto::PrefixedKey::TryParse(config.DiscoKey(), "discokey:");
        peer->Endpoints.clear();
        for (const std::string& endpoint : config.Endpoints())
        {
            if (std::optional<tailgate::net::Endpoint> parsed =
                    tailgate::net::Endpoint::TryParse(endpoint))
            {
                peer->Endpoints.push_back(*parsed);
            }
        }
        peer->Active = true;
        if (identityChanged || endpointsChanged || !config.Online())
        {
            m_connection.ResetPath(peer->PublicKey,
                                   identityChanged || !config.Online()
                                       ? tailgate::wgengine::magicsock::PeerPathState::ResetMode::
                                             ForgetVerifiedEndpoints
                                       : tailgate::wgengine::magicsock::PeerPathState::ResetMode::
                                             PreserveVerifiedEndpoints);
        }
    }
    for (PeerState& peer : m_peers)
    {
        if (!peer.Active)
        {
            (void)m_connection.RemovePeer(peer.PublicKey);
        }
    }
}

void SessionImpl::SetAdvertisedEndpoint(const tailgate::net::Endpoint& endpoint)
{
    m_advertisedEndpoint = endpoint;
}

void SessionImpl::SendPacket(const std::vector<std::uint8_t>& plaintext)
{
    if (m_configured)
    {
        Dispatch(m_protocol.Router().Send(plaintext));
    }
}

void SessionImpl::SendPacketTo(const tailgate::crypto::Bytes32& peer,
                               const std::vector<std::uint8_t>& plaintext)
{
    if (m_configured)
    {
        Dispatch(m_protocol.Router().SendTo(peer, plaintext));
    }
}

void SessionImpl::StartPeer(const tailgate::crypto::Bytes32& peer)
{
    if (m_configured)
    {
        Dispatch(m_protocol.Router().Start(peer));
    }
}

std::optional<tailgate::disco::Disco::TransactionId>
SessionImpl::SendDiscoPing(const tailgate::crypto::Bytes32& peerKey)
{
    PeerState* peer = FindPeer(peerKey);
    if (!m_configured || peer == nullptr || !peer->DiscoKey)
    {
        return std::nullopt;
    }
    const tailgate::disco::Disco::TransactionId transaction = m_protocol.Disco().NewTransactionId();
    const std::vector<std::uint8_t> ping =
        m_protocol.Disco().BuildPing(*peer->DiscoKey, transaction);
    SendRelay(*peer, ping, tailgate::derp::DerpSendQueue::Priority::Control);
    m_connection.ProbePeer(peerKey, ping);
    for (const tailgate::net::Endpoint& endpoint : peer->Endpoints)
    {
        (void)m_connection.TrySendProbe(endpoint, ping);
    }
    return transaction;
}

bool SessionImpl::CanDisco(const tailgate::crypto::Bytes32& peer) const noexcept
{
    const PeerState* state = FindPeer(peer);
    return m_configured && state != nullptr && state->DiscoKey.has_value();
}

std::optional<tailgate::wgengine::SessionPeerStats>
SessionImpl::PeerStats(const tailgate::crypto::Bytes32& peer) const noexcept
{
    const PeerState* state = FindPeer(peer);
    if (state == nullptr)
    {
        return std::nullopt;
    }
    return tailgate::wgengine::SessionPeerStats{
        .TransmittedBytes = state->TransmittedBytes,
        .ReceivedBytes = state->ReceivedBytes,
        .WireGuardSession = m_configured && m_protocol.Router().HasSession(peer),
        .DirectEndpoint = m_connection.DirectEndpoint(peer),
    };
}

SessionImpl::PeerState* SessionImpl::FindPeer(const tailgate::crypto::Bytes32& peer) noexcept
{
    const auto found = std::find_if(m_peers.begin(),
                                    m_peers.end(),
                                    [&](const PeerState& state)
                                    {
                                        return state.Active && state.PublicKey == peer;
                                    });
    return found == m_peers.end() ? nullptr : &*found;
}

const SessionImpl::PeerState*
SessionImpl::FindPeer(const tailgate::crypto::Bytes32& peer) const noexcept
{
    const auto found = std::find_if(m_peers.begin(),
                                    m_peers.end(),
                                    [&](const PeerState& state)
                                    {
                                        return state.Active && state.PublicKey == peer;
                                    });
    return found == m_peers.end() ? nullptr : &*found;
}

SessionImpl::PeerState*
SessionImpl::FindDiscoPeer(const tailgate::crypto::Bytes32& discoKey) noexcept
{
    const auto found = std::find_if(m_peers.begin(),
                                    m_peers.end(),
                                    [&](const PeerState& state)
                                    {
                                        return state.Active && state.DiscoKey == discoKey;
                                    });
    return found == m_peers.end() ? nullptr : &*found;
}

SessionImpl::DerpState* SessionImpl::FindDerp(int region) noexcept
{
    const auto found = std::find_if(m_derps.begin(),
                                    m_derps.end(),
                                    [&](const DerpState& derp)
                                    {
                                        return derp.Region == region;
                                    });
    if (found != m_derps.end())
    {
        return &*found;
    }
    return m_derps.empty() ? nullptr : &m_derps.front();
}

void SessionImpl::SendRelay(PeerState& peer,
                            const std::vector<std::uint8_t>& payload,
                            tailgate::derp::DerpSendQueue::Priority priority)
{
    DerpState* derp = FindDerp(peer.Config.DerpRegion());
    if (derp != nullptr)
    {
        derp->Connection->Send(peer.PublicKey, payload, priority);
    }
}

void SessionImpl::SendTransport(PeerState& peer,
                                const std::vector<std::uint8_t>& payload,
                                bool expectResponse,
                                tailgate::derp::DerpSendQueue::Priority priority)
{
    peer.TransmittedBytes += payload.size();
    if (m_connection.HasDirectPath(peer.PublicKey))
    {
        const tailgate::wgengine::magicsock::Connection::DirectSendResult sent =
            m_connection.Send(peer.PublicKey, payload, expectResponse);
        if (sent == tailgate::wgengine::magicsock::Connection::DirectSendResult::Sent ||
            sent == tailgate::wgengine::magicsock::Connection::DirectSendResult::Queued)
        {
            return;
        }
        m_connection.ResetPath(
            peer.PublicKey,
            tailgate::wgengine::magicsock::PeerPathState::ResetMode::PreserveVerifiedEndpoints);
    }
    SendRelay(peer, payload, priority);
}

void SessionImpl::StartDirectProbe(PeerState& peer)
{
    if (!m_configured || !peer.DiscoKey || m_connection.HasDirectPath(peer.PublicKey) ||
        !m_connection.TryBeginProbe(peer.PublicKey))
    {
        return;
    }
    base::Logger("magicsock")
        .LogTrace("probing peer={} candidates={} advertised={}",
                  crypto::BytesToHex(peer.PublicKey.data(), 8),
                  peer.Endpoints.size(),
                  m_advertisedEndpoint.Port() != 0);
    const tailgate::disco::Disco::TransactionId transaction = m_protocol.Disco().NewTransactionId();
    const std::vector<std::uint8_t> ping =
        m_protocol.Disco().BuildPing(*peer.DiscoKey, transaction);
    m_connection.ProbePeer(peer.PublicKey, ping);
    for (const tailgate::net::Endpoint& endpoint : peer.Endpoints)
    {
        (void)m_connection.TrySendProbe(endpoint, ping);
    }
    if (m_advertisedEndpoint.Port() != 0)
    {
        SendRelay(peer,
                  m_protocol.Disco().BuildCallMeMaybe(*peer.DiscoKey, {m_advertisedEndpoint}),
                  tailgate::derp::DerpSendQueue::Priority::Control);
    }
}

void SessionImpl::SetPacketPath(std::optional<std::reference_wrapper<PacketPath>> path)
{
    m_packetPath = path;
}

void SessionImpl::Dispatch(
    std::vector<tailgate::wgengine::wireguard::WireGuardRouter::TransportPacket> packets)
{
    for (const tailgate::wgengine::wireguard::WireGuardRouter::TransportPacket& packet : packets)
    {
        if (m_packetPath)
        {
            m_packetPath->get().Send(packet);
            continue;
        }
        PeerState* peer = FindPeer(packet.Peer);
        if (peer == nullptr)
        {
            continue;
        }
        if (!packet.Handshake)
        {
            SendTransport(*peer,
                          packet.Payload,
                          packet.ExpectResponse,
                          packet.Control ? tailgate::derp::DerpSendQueue::Priority::Control
                                         : tailgate::derp::DerpSendQueue::Priority::Data);
            continue;
        }
        StartDirectProbe(*peer);
        peer->TransmittedBytes += packet.Payload.size();
        SendRelay(*peer, packet.Payload, tailgate::derp::DerpSendQueue::Priority::Control);
        if (m_connection.HasDirectPath(peer->PublicKey))
        {
            (void)m_connection.Send(peer->PublicKey, packet.Payload, true);
            continue;
        }
        for (const tailgate::net::Endpoint& endpoint : peer->Endpoints)
        {
            (void)m_connection.TrySendProbe(endpoint, packet.Payload);
        }
    }
}

void SessionImpl::ProcessProtocolEvents(tailgate::wgengine::EngineWaitResult engineResult,
                                        tailgate::wgengine::SessionWaitResult& result)
{
    result.Packets = std::move(engineResult.Packets);
    result.Failures = std::move(engineResult.Failures);
    if (!result.Failures.empty() && m_discovery)
    {
        result.EndpointDiscovery = EndpointDiscoveryResult{};
        CancelEndpointDiscovery();
    }
    for (tailgate::types::nettype::UdpDatagram& datagram : engineResult.Datagrams)
    {
        if (!ProcessEndpointResponse(datagram, result) &&
            !ProcessDiscoPacket(nullptr, datagram.Source, std::nullopt, datagram.Payload, result) &&
            !ProcessWireGuardPacket(
                nullptr, datagram.Source, std::nullopt, datagram.Payload, result))
        {
            result.Datagrams.push_back(std::move(datagram));
        }
    }
    for (const tailgate::base::Event& event : engineResult.PlatformEvents)
    {
        if (m_control)
        {
            tailgate::control::client::ConnectionEventResult control =
                m_control->ProcessEvent(event);
            if (control.Handled)
            {
                result.NetworkMaps.insert(result.NetworkMaps.end(),
                                          std::make_move_iterator(control.NetworkMaps.begin()),
                                          std::make_move_iterator(control.NetworkMaps.end()));
                continue;
            }
        }
        bool handled = false;
        for (tailgate::wgengine::DerpConnectionId index = 0; index < m_derps.size(); ++index)
        {
            tailgate::derp::ConnectionEventResult derp =
                m_derps[index].Connection->ProcessEvent(event);
            if (!derp.Handled)
            {
                continue;
            }
            handled = true;
            for (tailgate::derp::DerpClient::Packet& packet : derp.Packets)
            {
                if (!ProcessDiscoPacket(
                        &packet.Source, std::nullopt, index, packet.Payload, result) &&
                    !ProcessWireGuardPacket(
                        &packet.Source, std::nullopt, index, packet.Payload, result))
                {
                    result.DerpPackets.push_back(tailgate::wgengine::SessionDerpPacket{
                        .Connection = index,
                        .Packet = std::move(packet),
                    });
                }
            }
            break;
        }
        if (!handled)
        {
            result.PlatformEvents.push_back(event);
        }
    }
}

bool SessionImpl::ProcessDiscoPacket(
    const tailgate::crypto::Bytes32* derpSource,
    const std::optional<tailgate::net::Endpoint>& directSource,
    std::optional<tailgate::wgengine::DerpConnectionId> derpConnection,
    const std::vector<std::uint8_t>& packet,
    tailgate::wgengine::SessionWaitResult& result)
{
    if (!m_configured || !tailgate::disco::Disco::IsDiscoPacket(packet))
    {
        return false;
    }
    const std::optional<tailgate::disco::Disco::Message> message = m_protocol.Disco().Parse(packet);
    if (!message)
    {
        return true;
    }
    PeerState* peer = FindDiscoPeer(message->Sender);
    if (peer == nullptr)
    {
        return true;
    }
    peer->ReceivedBytes += packet.size();
    if (message->Type == tailgate::disco::Disco::MessageType::CallMeMaybe)
    {
        if (derpSource != nullptr)
        {
            const tailgate::disco::Disco::TransactionId transaction =
                m_protocol.Disco().NewTransactionId();
            const std::vector<std::uint8_t> ping =
                m_protocol.Disco().BuildPing(*peer->DiscoKey, transaction);
            for (const tailgate::net::Endpoint& endpoint : message->Endpoints)
            {
                (void)m_connection.TrySendProbe(endpoint, ping);
            }
        }
    }
    else if (message->Type == tailgate::disco::Disco::MessageType::Ping)
    {
        const tailgate::net::Ipv4Address sourceAddress =
            directSource ? directSource->Address() : tailgate::disco::Disco::DerpMagicIpv4Address;
        const std::uint16_t sourcePort =
            directSource ? directSource->Port() : static_cast<std::uint16_t>(m_homeDerpRegion);
        const std::vector<std::uint8_t> pong = m_protocol.Disco().BuildPong(
            *peer->DiscoKey, message->Transaction, sourceAddress, sourcePort);
        if (directSource)
        {
            MarkDirect(*peer, *directSource, result);
            (void)m_connection.SendDirect(peer->PublicKey, *directSource, pong);
        }
        else if (derpSource != nullptr && derpConnection && *derpConnection < m_derps.size())
        {
            m_derps[*derpConnection].Connection->Send(
                *derpSource, pong, tailgate::derp::DerpSendQueue::Priority::Control);
            // A CLI Disco ping need not include CallMeMaybe or a WireGuard handshake.
            // Open the reverse UDP path as well: stateful firewalls/NATs can otherwise
            // keep this peer on DERP until the local user initiates traffic.
            StartDirectProbe(*peer);
        }
    }
    else if (message->Type == tailgate::disco::Disco::MessageType::Pong && directSource)
    {
        MarkDirect(*peer, *directSource, result);
    }
    result.DiscoEvents.push_back(tailgate::wgengine::SessionDiscoEvent{
        .Peer = peer->PublicKey,
        .Type = message->Type,
        .Transaction = message->Transaction,
        .DirectSource = directSource,
    });
    return true;
}

void SessionImpl::MarkDirect(PeerState& peer,
                             const tailgate::net::Endpoint& endpoint,
                             tailgate::wgengine::SessionWaitResult& result)
{
    if (m_connection.MarkDirect(peer.PublicKey, endpoint))
    {
        base::Logger("magicsock")
            .LogDebug("direct path selected peer={}", crypto::BytesToHex(peer.PublicKey.data(), 8));
        result.PathEvents.push_back(tailgate::wgengine::SessionPathEvent{
            .Peer = peer.PublicKey,
            .DirectEndpoint = endpoint,
        });
    }
}

bool SessionImpl::ProcessWireGuardPacket(
    const tailgate::crypto::Bytes32* source,
    const std::optional<tailgate::net::Endpoint>& directSource,
    std::optional<tailgate::wgengine::DerpConnectionId> derpConnection,
    const std::vector<std::uint8_t>& packet,
    tailgate::wgengine::SessionWaitResult& result)
{
    if (!m_configured || tailgate::disco::Disco::IsDiscoPacket(packet))
    {
        return false;
    }
    tailgate::wgengine::wireguard::WireGuardRouter::ReceiveResult received =
        source == nullptr ? m_protocol.Router().Receive(packet)
                          : m_protocol.Router().Receive(*source, packet);
    if (received.Source == tailgate::crypto::Bytes32{})
    {
        return false;
    }
    if (!received.Accepted)
    {
        return true;
    }
    PeerState* peer = FindPeer(received.Source);
    if (peer != nullptr)
    {
        peer->ReceivedBytes += packet.size();
        if (directSource)
        {
            MarkDirect(*peer, *directSource, result);
        }
    }
    for (const auto& outbound : received.Outbound)
    {
        if (peer != nullptr)
        {
            peer->TransmittedBytes += outbound.Payload.size();
        }
        if (directSource)
        {
            (void)m_connection.SendDirect(received.Source, *directSource, outbound.Payload);
        }
        else if (derpConnection && *derpConnection < m_derps.size())
        {
            m_derps[*derpConnection].Connection->Send(
                received.Source,
                outbound.Payload,
                outbound.Control ? tailgate::derp::DerpSendQueue::Priority::Control
                                 : tailgate::derp::DerpSendQueue::Priority::Data);
        }
    }
    result.WireGuardEvents.push_back(tailgate::wgengine::SessionWireGuardEvent{
        .Peer = received.Source,
        .Plaintext = std::move(received.Plaintext),
        .DirectSource = directSource,
        .TransportBytes = packet.size(),
        .SessionEstablished = received.SessionEstablished,
    });
    return true;
}

void SessionImpl::MaintainConnections(tailgate::wgengine::SessionWaitResult& result)
{
    if (m_control)
    {
        std::vector<tailgate::types::netmap::NetworkConfig> maps = m_control->Maintain();
        result.NetworkMaps.insert(result.NetworkMaps.end(),
                                  std::make_move_iterator(maps.begin()),
                                  std::make_move_iterator(maps.end()));
    }
    for (const DerpState& derp : m_derps)
    {
        derp.Connection->Maintain();
    }
}

void SessionImpl::Maintain(tailgate::wgengine::SessionWaitResult& result)
{
    MaintainConnections(result);
    if (m_configured)
    {
        Dispatch(m_protocol.Router().UpdateTimers());
        for (PeerState& peer : m_peers)
        {
            if (!peer.Active)
            {
                continue;
            }
            if (m_connection.ExpireDirectPath(peer.PublicKey))
            {
                base::Logger("magicsock")
                    .LogDebug("direct path expired peer={}",
                              crypto::BytesToHex(peer.PublicKey.data(), 8));
                result.PathEvents.push_back(tailgate::wgengine::SessionPathEvent{
                    .Peer = peer.PublicKey,
                    .DirectEndpoint = std::nullopt,
                });
            }
            if (m_protocol.Router().HasSession(peer.PublicKey) &&
                !m_connection.HasDirectPath(peer.PublicKey))
            {
                StartDirectProbe(peer);
            }
        }
    }
    result.MaintenanceDue = true;
    do
    {
        m_nextMaintenance += MaintenanceInterval;
    } while (m_nextMaintenance <= m_timeProvider.Now());
}

void SessionImpl::Wake() noexcept
{
    m_engine.Wake();
}

} // namespace tailgate::wgengine::impl
