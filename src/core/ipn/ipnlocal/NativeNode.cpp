#include "tailgate/ipn/ipnlocal/NativeNode.h"

#include <algorithm>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <tailgate/base/Logger.h>
#include <tailgate/ipn/ipnlocal/NodeError.h>
#include <tailgate/ipn/ipnlocal/NodeStatus.h>
#include <tailgate/net/dns/TailnetDns.h>

namespace tailgate::ipn::ipnlocal
{

NativeNode::NativeNode(wgengine::Session& session,
                       wgengine::Engine& engine,
                       wgengine::magicsock::Connection& udp,
                       LocalServices& services,
                       DnsForwarder& dns,
                       wgengine::ping::Tracker& pings,
                       base::TimeProvider& time,
                       DerpTransportFactory& derps)
    : m_session(session),
      m_engine(engine),
      m_udp(udp),
      m_time(time),
      m_dns(dns),
      m_pings(pings),
      m_runtime(services, dns, pings),
      m_derps(session, derps)
{
}

void NativeNode::Start(types::netmap::NetworkConfig network,
                       wgengine::SessionOptions options,
                       const wgengine::tstun::DeviceOptions& device,
                       types::nettype::UdpSocketOptions udp,
                       std::optional<net::Endpoint> stunServer,
                       bool enableDerp)
{
    if (m_started)
    {
        throw std::logic_error("native node transport is already started");
    }
    if (udp.ReadinessToken.Value == 0)
    {
        throw NodeError(NodeFailure::InvalidTransportOptions);
    }
    if (!m_engine.PacketDeviceOpen() && !m_engine.OpenPacketDevice(device))
    {
        throw std::system_error(std::make_error_code(std::errc::device_or_resource_busy));
    }
    options.Peers = network.Peers();
    if (options.HomeDerpRegion == 0)
    {
        options.HomeDerpRegion = network.DerpRegion();
    }
    const auto homeRegion = options.HomeDerpRegion;
    auto homeHost = network.DerpHost();
    for (const auto& peer : network.Peers())
    {
        if (peer.DerpRegion() == homeRegion && !peer.DerpHost().empty())
        {
            homeHost = peer.DerpHost();
            break;
        }
    }
    m_exitNode = options.ExitNode;
    m_policy = NetworkPolicy(m_exitNode);
    (void)m_policy.Apply(network);
    m_udpOptions = std::move(udp);
    m_stunServer = stunServer;
    m_session.Configure(std::move(options));
    m_derpEnabled = enableDerp;
    m_derps.SetEnabled(enableDerp);
    m_homeDerp = m_derps.Ensure(homeRegion, homeHost, true);
    m_derps.ApplyNetworkMap(network);
    m_runtime.SetNetworkConfig(network);
    m_network = std::move(network);
    m_started = true;
}

void NativeNode::UpdateNetwork(types::netmap::NetworkConfig network)
{
    if (!m_started)
    {
        throw std::logic_error("native node transport has not started");
    }
    if (network.Domain() != m_network.Domain() || network.SelfNodeId() != m_network.SelfNodeId() ||
        network.SelfKey() != m_network.SelfKey())
    {
        throw NodeError(NodeFailure::IdentityChanged);
    }
    m_derps.ApplyNetworkMap(network);
    (void)m_policy.Apply(network);
    m_session.UpdatePeers(network.Peers(), m_exitNode);
    m_runtime.SetNetworkConfig(network);
    m_network = std::move(network);
}

PacketDelivery NativeNode::Delivery()
{
    return PacketDelivery{
        .Host =
            [this](std::vector<std::uint8_t> packet)
        {
            const auto result = m_engine.WritePacket(std::move(packet));
            return result == wgengine::PacketWriteResult::Written ||
                   result == wgengine::PacketWriteResult::Queued;
        },
        .Network =
            [this](const std::vector<std::uint8_t>& packet)
        {
            m_session.SendPacket(packet);
        },
        .Peer =
            [this](const crypto::Bytes32& peer, const std::vector<std::uint8_t>& packet)
        {
            m_session.SendPacketTo(peer, packet);
        },
    };
}

wgengine::ping::StartStatus NativeNode::StartPing(const wgengine::ping::Request& request)
{
    if (!m_started)
    {
        throw std::logic_error("native node transport has not started");
    }
    const auto started = m_pings.Start(
        request,
        m_network,
        [this](const crypto::Bytes32& peer,
               const crypto::Bytes32&) -> std::optional<wgengine::ping::DiscoProbe>
        {
            const auto transaction = m_session.SendDiscoPing(peer);
            return transaction ? std::optional(wgengine::ping::DiscoProbe{
                                     .Transaction = *transaction, .Payload = {}})
                               : std::nullopt;
        },
        m_time.Now());
    if (started.Outbound && !started.Outbound->Disco)
    {
        m_session.SendPacketTo(started.Outbound->Peer, started.Outbound->Payload);
    }
    return started.Status;
}

void NativeNode::Poll(std::size_t maximumPackets)
{
    if (m_started)
    {
        PollUdpRebind();
        m_dns.Expire(m_time.Now());
        m_runtime.Poll(maximumPackets, Delivery());
    }
}

void NativeNode::ChangeNetwork(std::string networkInterface,
                               std::optional<net::Endpoint> stunServer)
{
    m_udpOptions.NetworkInterface = networkInterface;
    m_stunServer = stunServer;
    m_derps.ChangeNetwork(networkInterface);
    m_derps.SetEnabled(m_derpEnabled);
    ScheduleUdpRebind();
    m_nextUdpBind = m_time.Now();
    m_session.Wake();
}

void NativeNode::SuspendNetwork()
{
    m_session.CancelEndpointDiscovery();
    m_udp.Close();
    m_session.SetAdvertisedEndpoint({});
    m_derps.SetEnabled(false);
    m_udpBinding = false;
    m_nextUdpBind.reset();
    m_endpoints.reset();
}

void NativeNode::SetStunServer(std::optional<net::Endpoint> stunServer)
{
    m_stunServer = stunServer;
    m_session.CancelEndpointDiscovery();
    if (m_stunServer && m_udp.LocalEndpoint())
    {
        m_session.StartEndpointDiscovery(*m_stunServer, StunTimeout);
    }
}

void NativeNode::SetDerpEnabled(bool enabled)
{
    m_derpEnabled = enabled;
    m_derps.SetEnabled(enabled);
}

void NativeNode::Select()
{
    m_session.SetPacketPath(std::nullopt);
}

void NativeNode::PrepareTransport()
{
    ScheduleUdpRebind();
    m_nextUdpBind = m_time.Now();
    m_session.Wake();
}

void NativeNode::PollTransport()
{
    PollUdpRebind();
}

bool NativeNode::TransportPrepared() const
{
    return m_udp.LocalEndpoint().has_value();
}

std::optional<NativeEndpoints> NativeNode::TakeEndpoints()
{
    return std::exchange(m_endpoints, std::nullopt);
}

void NativeNode::ScheduleUdpRebind()
{
    // The packet device, DERP connections, WireGuard sessions, ping/DNS state and
    // local services all remain alive. Only the failed direct transport retires.
    m_session.CancelEndpointDiscovery();
    m_udp.Close();
    m_session.SetAdvertisedEndpoint({});
    m_session.UpdatePeers(m_network.Peers(), m_exitNode);
    m_udpBinding = false;
    m_endpoints.reset();
    m_nextUdpBind = m_time.Now() + m_rebindBackoff.NextDelay();
    base::Logger("native-node")
        .LogWarning("direct UDP unavailable; retaining DERP and local services");
}

void NativeNode::PollUdpRebind()
{
    if (!m_nextUdpBind)
    {
        return;
    }
    if (m_udpBinding)
    {
        if (const auto endpoint = m_udp.LocalEndpoint(); endpoint && endpoint->Port() != 0)
        {
            m_endpoints =
                NativeEndpoints{.BoundEndpoint = *endpoint, .PublicEndpoint = std::nullopt};
            if (m_stunServer)
            {
                m_session.StartEndpointDiscovery(*m_stunServer, StunTimeout);
            }
            m_nextUdpBind.reset();
            m_udpBinding = false;
            m_rebindBackoff.Reset();
            return;
        }
        if (m_time.Now() >= *m_nextUdpBind)
        {
            ScheduleUdpRebind();
        }
        return;
    }
    if (m_time.Now() < *m_nextUdpBind)
    {
        return;
    }
    try
    {
        if (m_udp.Rebind(m_udpOptions))
        {
            m_udpBinding = true;
            m_nextUdpBind = m_time.Now() + BindTimeout;
            return;
        }
    }
    catch (const std::system_error& error)
    {
        base::Logger("native-node").LogWarning("UDP rebind failed: {}", error.code().value());
    }
    ScheduleUdpRebind();
}

NodeEvents NativeNode::Wait(std::size_t maximumEvents,
                            std::size_t maximumPackets,
                            std::size_t maximumPacketSize)
{
    if (!m_started)
    {
        throw std::logic_error("native node transport has not started");
    }
    NodeEvents result;
    auto deadline = m_runtime.NextDeadline();
    if (m_nextUdpBind && (!deadline || *m_nextUdpBind < *deadline))
    {
        deadline = m_nextUdpBind;
    }
    result.Transport = m_session.Wait(maximumEvents, maximumPackets, maximumPacketSize, deadline);
    if (!result.Transport.Failures.empty())
    {
        ScheduleUdpRebind();
    }
    for (const auto& network : result.Transport.NetworkMaps)
    {
        UpdateNetwork(network);
        result.NetworkChanged = true;
    }
    const auto delivery = Delivery();
    for (const auto& packet : result.Transport.Packets)
    {
        m_runtime.HandleHostPacket(packet, delivery);
    }
    for (auto& event : result.Transport.WireGuardEvents)
    {
        for (auto& packet : event.Plaintext)
        {
            auto received =
                m_runtime.HandlePeerPacket(event.Peer, std::move(packet), m_time.Now(), delivery);
            received.DirectSource = event.DirectSource;
            result.Received.push_back(std::move(received));
        }
        event.Plaintext.clear();
    }
    result.Transport.Packets.clear();
    for (const auto& event : result.Transport.DiscoEvents)
    {
        if (event.Type == disco::Disco::MessageType::Pong)
        {
            if (auto ping = m_pings.CompleteDisco(event.Peer, event.Transaction, 0, m_time.Now()))
            {
                result.Received.push_back({.HostAvailable = true,
                                           .Dns = std::nullopt,
                                           .Ping = std::move(ping),
                                           .DirectSource = event.DirectSource});
            }
        }
    }
    const auto now = m_time.Now();
    for (auto& ping : m_pings.Expire(now))
    {
        result.Received.push_back({.HostAvailable = true,
                                   .Dns = std::nullopt,
                                   .Ping = std::move(ping),
                                   .DirectSource = std::nullopt});
    }
    (void)m_pings.RetryDisco(
        now,
        [this](const crypto::Bytes32& peer,
               const crypto::Bytes32&) -> std::optional<wgengine::ping::DiscoProbe>
        {
            const auto transaction = m_session.SendDiscoPing(peer);
            return transaction ? std::optional(wgengine::ping::DiscoProbe{
                                     .Transaction = *transaction, .Payload = {}})
                               : std::nullopt;
        });
    if (result.Transport.EndpointDiscovery && result.Transport.EndpointDiscovery->Endpoint)
    {
        if (const auto bound = m_udp.LocalEndpoint())
        {
            m_endpoints =
                NativeEndpoints{.BoundEndpoint = *bound,
                                .PublicEndpoint = result.Transport.EndpointDiscovery->Endpoint};
        }
    }
    Poll(maximumPackets);
    result.Endpoints = std::exchange(m_endpoints, std::nullopt);
    return result;
}

const types::netmap::NetworkConfig& NativeNode::Network() const noexcept
{
    return m_network;
}

void NativeNode::SetPeerApiPort(std::optional<std::uint16_t> port) noexcept
{
    m_runtime.SetPeerApiPort(port);
}

DnsForward NativeNode::ForwardDns(const net::Endpoint& client,
                                  std::vector<std::uint8_t> payload,
                                  const std::vector<std::string>& fallbackResolvers)
{
    auto result =
        m_dns.Begin(client, std::move(payload), m_policy, fallbackResolvers, m_time.Now());
    if (result.TunnelPacket)
    {
        if (auto reply = net::dns::TailnetDnsResponse::Build(m_network, *result.TunnelPacket))
        {
            result.LocalReply = m_dns.CompletePacket(*reply);
        }
        else
        {
            m_session.SendPacket(*result.TunnelPacket);
        }
    }
    return result;
}

std::optional<DnsReply> NativeNode::CompleteDns(const net::Endpoint& source,
                                                std::vector<std::uint8_t> payload)
{
    return m_dns.CompleteDatagram(source, std::move(payload));
}

void NativeNode::PublishEndpoints(const net::Endpoint& local,
                                  std::optional<net::Endpoint> publicEndpoint)
{
    m_session.SetAdvertisedEndpoint(local);
    if (auto* connection = m_session.ControlConnection())
    {
        std::vector<control::client::MapEndpoint> endpoints;
        if (publicEndpoint)
        {
            endpoints.push_back({.AddressPort = publicEndpoint->ToString(),
                                 .Type = control::client::EndpointType::Stun});
        }
        endpoints.push_back(
            {.AddressPort = local.ToString(), .Type = control::client::EndpointType::Local});
        connection->SetEndpoints(std::move(endpoints));
        connection->RequestReconnect();
    }
}

const NetworkPolicy& NativeNode::Policy() const noexcept
{
    return m_policy;
}

bool NativeNode::Connected() const
{
    return m_started &&
           m_session.DerpConnection(m_derps.Entries().at(m_homeDerp).Connection).Connected();
}

bool NativeNode::OwnershipReady() const
{
    if (!Connected())
    {
        return false;
    }
    for (const auto& peer : m_network.Peers())
    {
        if (peer.DerpRegion() <= 0)
        {
            continue;
        }
        const auto& regions = m_derps.Entries();
        const auto region = std::ranges::find(regions, peer.DerpRegion(), &DerpRuntime::Region);
        if (region == regions.end() || !m_session.DerpConnection(region->Connection).Connected())
        {
            return false;
        }
    }
    return true;
}

void NativeNode::UpdateStatus(Status& status) const
{
    NodeStatus snapshot(status);
    snapshot.UpdateStatistics(m_session, m_network);
}

bool NativeNode::Ready() const noexcept
{
    return m_started;
}

void NativeNode::Shutdown()
{
    // Socket/session ownership remains with the caller's scope; there is no native shutdown frame.
    m_session.CancelEndpointDiscovery();
}

} // namespace tailgate::ipn::ipnlocal
