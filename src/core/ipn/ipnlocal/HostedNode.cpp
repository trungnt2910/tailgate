#include "tailgate/ipn/ipnlocal/HostedNode.h"

#include <algorithm>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <tailgate/hosted/DiscoProbes.h>
#include <tailgate/ipn/ipnlocal/NodeError.h>
#include <tailgate/ipn/ipnlocal/NodeStatus.h>
#include <tailgate/wgengine/magicsock/PeerPathState.h>

namespace tailgate::ipn::ipnlocal
{
namespace
{

constexpr auto HeartbeatInterval = std::chrono::seconds(20);
constexpr auto MaintenanceInterval = std::chrono::seconds(1);

} // namespace

HostedNode::HostedNode(hosted::Client& client,
                       wgengine::Session& session,
                       wgengine::Engine& engine,
                       LocalServices& services,
                       DnsForwarder& dns,
                       wgengine::ping::Tracker& pings,
                       base::TimeProvider& time,
                       hosted::Dns& hostedDns,
                       hosted::Recovery& recovery)
    : m_client(client),
      m_session(session),
      m_engine(engine),
      m_dns(dns),
      m_pings(pings),
      m_time(time),
      m_hostedDns(hostedDns),
      m_recovery(recovery),
      m_runtime(services, dns, pings)
{
}

void HostedNode::Start(hosted::ConnectionResult connection,
                       const wgengine::tstun::DeviceOptions& device,
                       std::string exitNode,
                       std::string relayName)
{
    if (m_stream)
    {
        throw std::logic_error("hosted node requires a newly authenticated relay");
    }
    if (!m_engine.PacketDeviceOpen() && !m_engine.OpenPacketDevice(device))
    {
        throw std::system_error(std::make_error_code(std::errc::device_or_resource_busy));
    }

    m_exitNode = std::move(exitNode);
    m_relayName = std::move(relayName);
    m_policy = NetworkPolicy(m_exitNode);
    m_network = connection.Configuration.Network;
    m_recovery.Configure(connection.Reconnect);
    (void)m_policy.Apply(m_network);
    m_runtime.SetNetworkConfig(m_network);
    m_nextHeartbeat = m_time.Now() + HeartbeatInterval;
    m_nextProbe = m_time.Now();
    m_nextMaintenance = m_time.Now();
    ReplaceTransport(std::move(connection));
}

void HostedNode::ReplaceTransport(hosted::ConnectionResult connection)
{
    if (connection.Configuration.Network.Domain() != m_network.Domain() ||
        connection.Configuration.Network.SelfNodeId() != m_network.SelfNodeId() ||
        connection.Configuration.Network.SelfKey() != m_network.SelfKey())
    {
        throw NodeError(NodeFailure::IdentityChanged);
    }
    // A candidate may have taken time to authenticate. Use the current map, never
    // replace it with the worker's snapshot. Protocol.Initialize retains peer sessions.
    connection.Configuration.Network = m_network;
    connection.Configuration.ExitNode = m_exitNode;
    m_stream = std::make_unique<hosted::StreamTransport>(std::move(connection.Stream),
                                                         std::move(connection.FrameDecoder));
    m_ready = false;
    Queue(m_client.Start(std::move(connection.Configuration)));
    Queue(m_client.BuildKeepAlive());
    m_session.Wake();
}

void HostedNode::RetireTransport() noexcept
{
    m_stream.reset();
    m_ready = false;
}

void HostedNode::Select()
{
    m_session.SetPacketPath(std::ref(*this));
}

void HostedNode::Send(const wgengine::wireguard::WireGuardRouter::TransportPacket& packet)
{
    Queue(hosted::Frame(hosted::MessageType::ClientPacket,
                        hosted::ProtocolCodec::EncodePeerPacket(
                            hosted::PeerPacket(packet.Peer, packet.Payload, packet.Control)))
              .Encode());
}

bool HostedNode::HasTransport() const noexcept
{
    return m_stream != nullptr;
}

void HostedNode::StopRecovery()
{
    m_recovery.Cancel();
}

void HostedNode::ResumeRecovery()
{
    m_recovery.Failed();
}

NodeEvents HostedNode::PollTransport(std::size_t maximumPackets)
{
    NodeEvents result;
    Poll(result, maximumPackets, false);
    return result;
}

void HostedNode::RequestDelegation(const hosted::DelegationRequest& request)
{
    if (!m_stream)
    {
        throw std::system_error(std::make_error_code(std::errc::not_connected));
    }
    Queue(hosted::EncodeDelegation(request).Encode());
    m_session.Wake();
}

std::uint64_t HostedNode::MapRevision() const noexcept
{
    return m_client.MapRevision();
}

void HostedNode::ChangeNetwork(std::string networkInterface)
{
    RetireTransport();
    m_recovery.ChangeNetwork(std::move(networkInterface));
}

void HostedNode::UpdateNetwork(types::netmap::NetworkConfig network)
{
    if (network.Domain() != m_network.Domain() || network.SelfNodeId() != m_network.SelfNodeId() ||
        network.SelfKey() != m_network.SelfKey())
    {
        throw NodeError(NodeFailure::IdentityChanged);
    }
    (void)m_policy.Apply(network);
    const auto effectiveExit = m_policy.ExitPeer() ? m_exitNode : std::string{};
    Queue(m_client.UpdateNetworkMap(network, effectiveExit));
    m_network = std::move(network);
    m_runtime.SetNetworkConfig(m_network);
}

void HostedNode::Queue(std::vector<std::uint8_t> bytes)
{
    if (m_stream && !m_stream->Queue(std::move(bytes)))
    {
        throw std::system_error(std::make_error_code(std::errc::no_buffer_space));
    }
}

PacketDelivery HostedNode::Delivery()
{
    return {.Host =
                [this](std::vector<std::uint8_t> bytes)
            {
                const auto result = m_engine.WritePacket(std::move(bytes));
                return result == wgengine::PacketWriteResult::Written ||
                       result == wgengine::PacketWriteResult::Queued;
            },
            .Network =
                [this](const std::vector<std::uint8_t>& bytes)
            {
                Queue(m_client.Encapsulate(bytes));
            },
            .Peer =
                [this](const crypto::Bytes32& peer, const std::vector<std::uint8_t>& bytes)
            {
                Queue(m_client.EncapsulateTo(peer, bytes));
            }};
}

void HostedNode::SendProbe(const wgengine::ping::Probe& packet)
{
    if (packet.Disco)
    {
        Queue(hosted::Frame(hosted::MessageType::ClientPacket,
                            hosted::ProtocolCodec::EncodePeerPacket(
                                hosted::PeerPacket(packet.Peer, packet.Payload, false, true)))
                  .Encode());
    }
    else
    {
        Queue(m_client.EncapsulateTo(packet.Peer, packet.Payload));
    }
}

wgengine::ping::StartStatus HostedNode::StartPing(const wgengine::ping::Request& request)
{
    auto options = request;
    options.Relay = m_relayName;
    const auto started = m_pings.Start(
        options,
        m_network,
        [this](const crypto::Bytes32&, const crypto::Bytes32& key)
        {
            return wgengine::ping::DiscoProbe::Build(m_client.Disco(), key);
        },
        m_time.Now());
    if (started.Outbound)
    {
        SendProbe(*started.Outbound);
    }
    return started.Status;
}

DnsForward HostedNode::ForwardDns(const net::Endpoint& client,
                                  std::vector<std::uint8_t> payload,
                                  const std::vector<std::string>& fallbackResolvers)
{
    auto result =
        m_dns.Begin(client, std::move(payload), m_policy, fallbackResolvers, m_time.Now());
    if (result.TunnelPacket)
    {
        auto query = m_hostedDns.ProcessQuery(*result.TunnelPacket, m_network);
        if (query.Status == hosted::DnsStatus::Complete)
        {
            Queue(query.RemoteFrame->Encode());
        }
        else
        {
            Queue(m_client.Encapsulate(*result.TunnelPacket));
        }
    }
    return result;
}

std::optional<DnsReply> HostedNode::CompleteDns(const net::Endpoint& source,
                                                std::vector<std::uint8_t> payload)
{
    return m_dns.CompleteDatagram(source, std::move(payload));
}

void HostedNode::Receive(const hosted::Frame& frame, NodeEvents& result)
{
    auto dns = m_hostedDns.ProcessResponse(frame, m_network);
    if (dns.Status == hosted::DnsStatus::Invalid)
    {
        throw std::system_error(std::make_error_code(std::errc::protocol_error));
    }
    if (dns.Status == hosted::DnsStatus::Complete)
    {
        auto reply = m_dns.CompletePacket(*dns.LocalPacket);
        if (reply)
        {
            result.Received.push_back(
                {.HostAvailable = true, .Dns = std::move(reply), .Ping = {}, .DirectSource = {}});
        }
        else if (!Delivery().Host(std::move(*dns.LocalPacket)))
        {
            throw std::system_error(std::make_error_code(std::errc::no_buffer_space));
        }
        return;
    }
    auto processed = m_client.Process(frame);
    Queue(std::move(processed.RemoteOutput));
    if (processed.NetworkMapChanged)
    {
        UpdateNetwork(m_client.Network());
        result.NetworkChanged = true;
    }
    if (processed.Delegation)
    {
        result.DelegationReplies.push_back(*processed.Delegation);
    }
    if (processed.AppliedMapRevision)
    {
        result.AppliedMapRevision = processed.AppliedMapRevision;
    }
    result.DataPathReady |= processed.DataPathReady;
    m_ready |= processed.DataPathReady;
    if (processed.Pong)
    {
        auto ping = m_pings.CompleteDisco(
            processed.Pong->Packet.Peer(), processed.Pong->Message.Transaction, 0, m_time.Now());
        if (ping)
        {
            result.Received.push_back(
                {.HostAvailable = true, .Dns = {}, .Ping = std::move(ping), .DirectSource = {}});
        }
    }
    for (auto& packet : processed.LocalPackets)
    {
        result.Received.push_back(m_runtime.HandlePeerPacket(
            packet.Peer, std::move(packet.Bytes), m_time.Now(), Delivery()));
    }
    if (frame.Type() == hosted::MessageType::Heartbeat)
    {
        m_nextHeartbeat = m_time.Now() + HeartbeatInterval;
    }
}

void HostedNode::Poll(NodeEvents& result, std::size_t maximumPackets, bool processLocal)
{
    if (auto replacement = m_recovery.Poll())
    {
        ReplaceTransport(std::move(*replacement));
    }
    if (m_stream)
    {
        try
        {
            for (const auto& frame : m_stream->Receive(maximumPackets, maximumPackets))
            {
                Receive(frame, result);
            }
        }
        catch (const std::system_error& error)
        {
            result.TransportFailure = error.code();
            RetireTransport();
            m_recovery.Failed();
        }
    }
    const auto now = m_time.Now();
    if (now >= m_nextHeartbeat)
    {
        Queue(m_client.BuildKeepAlive());
        m_nextHeartbeat = now + HeartbeatInterval;
    }
    if (processLocal && now >= m_nextMaintenance)
    {
        Queue(m_client.UpdateTimers());
        m_nextMaintenance = now + MaintenanceInterval;
    }
    if (processLocal && now >= m_nextProbe)
    {
        Queue(m_client.ProbePeers());
        m_nextProbe = now + wgengine::magicsock::PeerPathState::DirectProbeInterval;
    }
    if (processLocal)
    {
        for (auto& ping : m_pings.Expire(now))
        {
            result.Received.push_back(
                {.HostAvailable = true, .Dns = {}, .Ping = std::move(ping), .DirectSource = {}});
        }
        for (const auto& probe :
             m_pings.RetryDisco(now,
                                [this](const crypto::Bytes32&, const crypto::Bytes32& key)
                                {
                                    return wgengine::ping::DiscoProbe::Build(m_client.Disco(), key);
                                }))
        {
            SendProbe(probe);
        }
        m_dns.Expire(now);
        m_runtime.Poll(maximumPackets, Delivery());
    }
    if (m_stream)
    {
        try
        {
            const bool moreOutput = m_stream->Flush(maximumPackets);
            if (moreOutput || m_stream->HasBufferedInput())
            {
                m_session.Wake();
            }
        }
        catch (const std::system_error& error)
        {
            result.TransportFailure = error.code();
            RetireTransport();
            m_recovery.Failed();
        }
    }
}

NodeEvents HostedNode::Wait(std::size_t maximumEvents,
                            std::size_t maximumPackets,
                            std::size_t maximumPacketSize)
{
    NodeEvents result;
    Poll(result, maximumPackets);
    if (result.NetworkChanged || result.DataPathReady || result.TransportFailure ||
        !result.DelegationReplies.empty() || result.AppliedMapRevision || !result.Received.empty())
    {
        m_session.Wake();
    }
    auto deadline = std::min({m_nextHeartbeat, m_nextMaintenance, m_nextProbe});
    if (const auto local = m_runtime.NextDeadline())
    {
        deadline = std::min(deadline, *local);
    }
    if (const auto retry = m_recovery.Deadline())
    {
        deadline = std::min(deadline, *retry);
    }
    result.Transport = m_session.Wait(maximumEvents, maximumPackets, maximumPacketSize, deadline);
    for (const auto& update : result.Transport.NetworkMaps)
    {
        UpdateNetwork(update);
        result.NetworkChanged = true;
    }
    for (const auto& packet : result.Transport.Packets)
    {
        m_runtime.HandleHostPacket(packet, Delivery());
    }
    for (auto& event : result.Transport.WireGuardEvents)
    {
        for (auto& packet : event.Plaintext)
        {
            auto received =
                m_runtime.HandlePeerPacket(event.Peer, std::move(packet), m_time.Now(), Delivery());
            received.DirectSource = event.DirectSource;
            result.Received.push_back(std::move(received));
        }
        event.Plaintext.clear();
    }
    for (const auto& event : result.Transport.DiscoEvents)
    {
        if (event.Type == disco::Disco::MessageType::Pong)
        {
            if (auto ping = m_pings.CompleteDisco(event.Peer, event.Transaction, 0, m_time.Now()))
            {
                result.Received.push_back({.HostAvailable = true,
                                           .Dns = {},
                                           .Ping = std::move(ping),
                                           .DirectSource = event.DirectSource});
            }
        }
    }
    result.Transport.Packets.clear();
    Poll(result, maximumPackets);
    return result;
}

const types::netmap::NetworkConfig& HostedNode::Network() const noexcept
{
    return m_network;
}

const NetworkPolicy& HostedNode::Policy() const noexcept
{
    return m_policy;
}

bool HostedNode::Ready() const noexcept
{
    return m_ready;
}

void HostedNode::Shutdown()
{
    m_recovery.Cancel();
    Queue(hosted::Frame(hosted::MessageType::Shutdown, {}).Encode());
    if (m_stream)
    {
        (void)m_stream->Flush(1);
    }
}

void HostedNode::SetPeerApiPort(std::optional<std::uint16_t> port) noexcept
{
    m_runtime.SetPeerApiPort(port);
}

void HostedNode::UpdateStatus(Status& status) const
{
    NodeStatus(status).ApplyNetwork(m_network);
}

void HostedNode::PublishEndpoints(const net::Endpoint&, std::optional<net::Endpoint>)
{
    // Hosted endpoint candidates belong to the relay and arrive through its authenticated protocol.
    throw std::logic_error("a hosted backend cannot publish native endpoints");
}

} // namespace tailgate::ipn::ipnlocal
