#include "NodeHost.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <format>
#include <map>
#include <memory>
#include <system_error>
#include <vector>

#include <arpa/inet.h>
#include <unistd.h>

#include <tailgate/base/Logger.h>
#include <tailgate/ipn/ipnlocal/NodeStatus.h>
#include <tailgate/ipn/ipnlocal/UnderlayResolver.h>
#include <tailgate/ipn/ipnlocal/UnderlaySelection.h>

#include "DataplaneEvents.h"
#include "Files.h"
#include "Lifecycle.h"
#include "Network.h"
#include "NetworkMonitor.h"
#include "PeerApiServer.h"
#include "PingIpc.h"
#include "StatusWriter.h"
#include "UnderlayResolver.h"
#include "UniqueFd.h"

namespace tailgate::linux_frontend
{
namespace
{

constexpr std::size_t MaximumPacketsPerTurn = 16;
constexpr std::size_t PacketBufferSize = 4096;
constexpr auto StatusInterval = std::chrono::seconds(10);
constexpr int Mtu = 1280;
constexpr std::uint16_t FunnelPeerApiPort = 41112;

net::Endpoint Endpoint(const sockaddr_in& address)
{
    return net::Endpoint(net::Ipv4Address::FromHostOrder(ntohl(address.sin_addr.s_addr)),
                         ntohs(address.sin_port));
}

sockaddr_in Address(const net::Endpoint& endpoint)
{
    sockaddr_in result{};
    result.sin_family = AF_INET;
    result.sin_addr.s_addr = htonl(endpoint.Address().HostOrder());
    result.sin_port = htons(endpoint.Port());
    return result;
}

struct PingClient
{
    sockaddr_un Address{};
    socklen_t Length = 0;
};

} // namespace

NodeHost::NodeHost(ipn::ipnlocal::NodeBackend& node,
                   wgengine::Session& session,
                   event::EventRegistry& events,
                   HostedConnectionRegistry& hostedConnections,
                   base::TimeProvider& time,
                   DaemonStatus& status)
    : m_node(node),
      m_session(session),
      m_events(events),
      m_hostedConnections(hostedConnections),
      m_time(time),
      m_status(status)
{
}

void NodeHost::Run(const NodeHostOptions& options,
                   int& readyFd,
                   ModeControl& modes,
                   base::EventLoop& events)
{
    auto network = m_node.Network();
    auto underlayInterface = options.UnderlayInterface;
    NetworkMonitor monitor(m_events, options.InterfaceName);
    ipn::ipnlocal::UnderlaySelection selection(m_time);
    selection.Start(monitor.Current(), underlayInterface);
    UnderlayResolver platformResolver;
    ipn::ipnlocal::UnderlayResolver resolver(platformResolver, events, m_time);
    const auto resolveStun = [&]()
    {
        resolver.Start(network.StunHost().empty() ? network.DerpHost() : network.StunHost(),
                       network.StunPort(),
                       underlayInterface);
    };
    resolveStun();
    const auto originalResolvers = ReadResolverAddresses();
    UniqueFd localDns = options.AcceptDns ? OpenLocalDnsSocket() : UniqueFd{};
    UniqueFd upstreamDns = OpenUdpSocket(options.UnderlayInterface);
    UniqueFd pingServer = OpenPingServer();
    const auto registerInput = [this](int descriptor, DataplaneEvent::Kind kind)
    {
        return m_events.Register(
            descriptor, event::EventInterest::Readable, DataplaneEvent(kind).Token());
    };
    event::EventHandle dnsEvent;
    if (localDns.Fd >= 0)
    {
        dnsEvent = registerInput(localDns.Fd, DataplaneEvent::Kind::LocalDns);
    }
    auto upstreamEvent = registerInput(upstreamDns.Fd, DataplaneEvent::Kind::UpstreamDns);
    auto pingEvent = registerInput(pingServer.Fd, DataplaneEvent::Kind::Ping);
    const auto configureAddresses = [&]()
    {
        SetInterfaceAddress(options.InterfaceName, network.SelfAddress());
        if (!network.FirstIpv6Address().empty())
        {
            SetInterfaceIpv6Address(options.InterfaceName, network.FirstIpv6Address());
        }
        SetInterfaceMtu(options.InterfaceName, Mtu);
    };
    configureAddresses();
    auto routes = m_node.Policy().Routes();
    for (const auto& route : routes.Routes())
    {
        AddRoute(options.InterfaceName, route);
    }
    if (options.AcceptDns)
    {
        WriteResolver("127.0.0.1", network.DnsDomains());
    }
    std::vector<std::unique_ptr<PeerApiServer>> peerApiServers;
    if (serve::IsEnabled(options.Funnel))
    {
        const auto host = network.SelfName().empty() ? network.DisplayName() : network.SelfName();
        const auto target = serve::TargetHostPort(host, options.Funnel.Port);
        for (const auto& address : {network.SelfAddress(), network.FirstIpv6Address()})
        {
            if (!address.empty())
            {
                peerApiServers.push_back(std::make_unique<PeerApiServer>(address,
                                                                         FunnelPeerApiPort,
                                                                         target,
                                                                         options.Funnel.LocalPort,
                                                                         options.CertificatePem,
                                                                         options.PrivateKeyPem));
            }
        }
    }
    m_node.SetPeerApiPort(serve::IsEnabled(options.Funnel) ? FunnelPeerApiPort : 0);
    ipn::ipnlocal::NodeStatus status(m_status);
    status.ApplyNetwork(network);
    WriteDaemonStatus(m_status);
    if (readyFd >= 0 && m_node.Ready())
    {
        const char ready = '1';
        if (write(readyFd, &ready, 1) != 1)
        {
            base::Logger("daemon").LogWarning("failed to notify parent that the tunnel is ready");
        }
        close(readyFd);
        readyFd = -1;
    }
    StatusWriter writer;
    std::map<std::uint64_t, PingClient> pings;
    std::uint64_t nextPing = 1;
    auto nextStatus = m_time.Now() + StatusInterval;
    while (!Lifecycle::Stopping())
    {
        if (Lifecycle::Reloading())
        {
            if (!modes.Reload())
            {
                break;
            }
            Lifecycle::ClearReload();
        }
        if (const auto change = selection.Poll(monitor.Current(), modes.TransportReady()))
        {
            resolver.Cancel();
            modes.SetStunServer(std::nullopt);
            const auto selected = change->Network ? change->Network->Interface : std::nullopt;
            if (auto* control = m_session.ControlConnection())
            {
                control->SetEndpoints({});
                control->ChangeNetwork(selected);
            }
            modes.ChangeNetwork(selected);
            upstreamEvent.Reset();
            upstreamDns.Reset();
            if (selected)
            {
                underlayInterface = *selected;
                upstreamDns = OpenUdpSocket(underlayInterface);
                upstreamEvent = registerInput(upstreamDns.Fd, DataplaneEvent::Kind::UpstreamDns);
                resolveStun();
            }
        }
        if (const auto resolved = resolver.Poll())
        {
            modes.SetStunServer(resolved);
        }
        if (modes.UpdateStatus(m_status))
        {
            writer.Submit(m_status);
        }
        const auto eventCount =
            std::max<std::size_t>(16, network.Peers().size() + m_session.DerpConnectionCount() + 7);
        auto completed = m_node.Wait(eventCount, MaximumPacketsPerTurn, PacketBufferSize);
        for (const auto& event : completed.Transport.PlatformEvents)
        {
            monitor.ProcessEvent(event);
        }
        if (m_node.Ready() && readyFd >= 0)
        {
            const char ready = '1';
            (void)write(readyFd, &ready, 1);
            close(readyFd);
            readyFd = -1;
        }
        if (completed.NetworkChanged)
        {
            network = m_node.Network();
            configureAddresses();
            ApplyRouteChanges(options.InterfaceName, routes, m_node.Policy().Routes());
            routes = m_node.Policy().Routes();
            if (options.AcceptDns)
            {
                WriteResolver("127.0.0.1", network.DnsDomains());
            }
            m_hostedConnections.UpdateNetworkMap(network);
            status.ApplyNetwork(network);
            writer.Submit(m_status);
        }
        if (completed.Endpoints)
        {
            const auto local = net::Endpoint(
                net::Ipv4Address::FromHostOrder(InterfaceIpv4Address(underlayInterface)),
                completed.Endpoints->BoundEndpoint.Port());
            m_node.PublishEndpoints(local, completed.Endpoints->PublicEndpoint);
        }
        for (const auto& received : completed.Received)
        {
            if (!received.HostAvailable)
            {
                throw std::system_error(std::make_error_code(std::errc::no_buffer_space));
            }
            if (received.Dns)
            {
                SendUdp(localDns.Fd, Address(received.Dns->Client), received.Dns->Payload);
            }
            if (received.Ping)
            {
                const auto client = pings.find(received.Ping->RequestId);
                if (client != pings.end())
                {
                    const auto& result = *received.Ping;
                    PingResponse response;
                    response.Responded = result.Responded;
                    response.LatencyMilliseconds = static_cast<int>(
                        std::chrono::duration_cast<std::chrono::milliseconds>(result.Latency)
                            .count());
                    response.NodeName = result.PeerName;
                    response.NodeAddress = result.PeerAddress;
                    response.Endpoint =
                        received.DirectSource ? received.DirectSource->ToString() : std::string{};
                    const auto peer =
                        std::ranges::find_if(network.Peers(),
                                             [&](const auto& candidate)
                                             {
                                                 return candidate.Address() == result.PeerAddress;
                                             });
                    if (peer != network.Peers().end())
                    {
                        response.Endpoint = m_hostedConnections.PathForNode(peer->NodeId())
                                                .value_or(response.Endpoint);
                    }
                    if (!options.RelayName.empty())
                    {
                        response.Endpoint = std::format("tailgate({})", options.RelayName);
                    }
                    response.Relay = result.Relay;
                    response.PeerApiPort = result.PeerApiPort;
                    SendPingResponse(
                        pingServer.Fd, client->second.Address, client->second.Length, response);
                    pings.erase(client);
                }
            }
        }
        status.UpdatePaths(completed.Transport, network);
        if (completed.Transport.MaintenanceDue)
        {
            m_node.UpdateStatus(m_status);
        }
        if (!completed.Transport.PathEvents.empty() || m_time.Now() >= nextStatus)
        {
            writer.Submit(m_status);
            nextStatus = m_time.Now() + StatusInterval;
        }
        for (const auto& event : completed.Transport.PlatformEvents)
        {
            if (!base::HasReadiness(event.Readiness, base::EventReadiness::Readable))
            {
                continue;
            }
            switch (DataplaneEvent::FromValue(event.Token.Value).Type())
            {
            case DataplaneEvent::Kind::LocalDns:
            {
                sockaddr_in client{};
                auto payload = ReceiveUdp(localDns.Fd, &client);
                auto forward =
                    m_node.ForwardDns(Endpoint(client), std::move(payload), originalResolvers);
                if (forward.Status == ipn::ipnlocal::DnsForwardStatus::UnsupportedResolver)
                {
                    throw std::system_error(
                        std::make_error_code(std::errc::protocol_not_supported));
                }
                if (forward.Status == ipn::ipnlocal::DnsForwardStatus::Ready &&
                    !forward.TunnelPacket && upstreamDns.Fd >= 0)
                {
                    (void)TrySendUdp(upstreamDns.Fd, Address(forward.Resolver), forward.Payload);
                }
                if (forward.LocalReply)
                {
                    SendUdp(localDns.Fd,
                            Address(forward.LocalReply->Client),
                            forward.LocalReply->Payload);
                }
                break;
            }
            case DataplaneEvent::Kind::UpstreamDns:
            {
                sockaddr_in source{};
                auto payload = ReceiveUdp(upstreamDns.Fd, &source);
                if (const auto reply = m_node.CompleteDns(Endpoint(source), std::move(payload)))
                {
                    SendUdp(localDns.Fd, Address(reply->Client), reply->Payload);
                }
                break;
            }
            case DataplaneEvent::Kind::Ping:
            {
                PingRequest request;
                PingClient client;
                client.Length = sizeof(client.Address);
                if (ReceivePingRequest(pingServer.Fd, request, client.Address, client.Length))
                {
                    const auto id = nextPing++;
                    const auto started = m_node.StartPing(
                        {.Id = id,
                         .Target = request.Target,
                         .PingMode = request.Tsmp ? wgengine::ping::Mode::Tsmp
                                                  : wgengine::ping::Mode::Disco,
                         .Timeout = std::chrono::seconds(std::max(1, request.TimeoutSeconds)),
                         .Relay = {}});
                    if (started == wgengine::ping::StartStatus::Ready)
                    {
                        pings.emplace(id, client);
                    }
                    else
                    {
                        SendPingResponse(pingServer.Fd, client.Address, client.Length, {});
                    }
                }
                break;
            }
            default:
                break;
            }
        }
    }
    if (Lifecycle::Stopping())
    {
        m_node.Shutdown();
    }
    std::filesystem::remove(PingSocketPath());
}

} // namespace tailgate::linux_frontend
