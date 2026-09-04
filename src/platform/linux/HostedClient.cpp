// libc++ 22 implements C++20 syncstream behind this opt-in. It must be enabled before
// any standard-library header includes libc++'s configuration.
#define _LIBCPP_ENABLE_EXPERIMENTAL

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <deque>
#include <exception>
#include <filesystem>
#include <format>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <syncstream>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <net/route.h>
#include <netdb.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <boost/algorithm/string/join.hpp>
#include <boost/di.hpp>

#include <tailgate/PlatformFrontend.h>
#include <tailgate/base/Logging.h>
#include <tailgate/cli/Arguments.h>
#include <tailgate/control/client/Connection.h>
#include <tailgate/control/client/RetryBackoff.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/derp/Client.h>
#include <tailgate/derp/Connection.h>
#include <tailgate/disco/Disco.h>
#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/ClientSession.h>
#include <tailgate/hosted/Connection.h>
#include <tailgate/hosted/DiscoProbes.h>
#include <tailgate/hosted/Dns.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/hosted/ServerSession.h>
#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/dns/ResolverSelection.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/net/packet/Tsmp.h>
#include <tailgate/qr/QrCode.h>
#include <tailgate/serve/FunnelConfig.h>
#include <tailgate/serve/acme/Client.h>
#include <tailgate/types/nettype/TcpSocket.h>
#include <tailgate/wgengine/Session.h>
#include <tailgate/wgengine/magicsock/Connection.h>
#include <tailgate/wgengine/magicsock/PeerPathState.h>
#include <tailgate/wgengine/ping/Tracker.h>
#include <tailgate/wgengine/router/Config.h>
#include <tailgate/wgengine/wireguard/Router.h>

#include "DI.h"
#include "DataplaneEvents.h"
#include "Files.h"
#include "HostedConnectionRegistry.h"
#include "Network.h"
#include "PeerApiServer.h"
#include "PingIpc.h"
#include "QrCode.h"
#include "RelayServer.h"
#include "State.h"
#include "StatusWriter.h"
#include "UniqueFd.h"
#include "event/EventRegistry.h"
#include "impl/TcpStream.h"

#include "HostedClient.h"
#include "HostedServer.h"
#include "Lifecycle.h"
#include "TunnelRunner.h"

namespace
{

using tailgate::linux_frontend::AddRoute;
using tailgate::linux_frontend::ApplyRouteChanges;
using tailgate::linux_frontend::DataplaneEvent;
using tailgate::linux_frontend::DefaultRouteInterface;
using tailgate::linux_frontend::InterfaceIpv4Address;
using tailgate::linux_frontend::Lifecycle;
using tailgate::linux_frontend::OpenLocalDnsSocket;
using tailgate::linux_frontend::OpenUdpSocket;
using tailgate::linux_frontend::ParseIpv4Endpoint;
using tailgate::linux_frontend::ReadResolverAddresses;
using tailgate::linux_frontend::ReceiveUdp;
using tailgate::linux_frontend::RemoveRoute;
using tailgate::linux_frontend::SendUdp;
using tailgate::linux_frontend::SetInterfaceAddress;
using tailgate::linux_frontend::SetInterfaceIpv6Address;
using tailgate::linux_frontend::SetInterfaceMtu;
using tailgate::linux_frontend::TryParseIpv4Endpoint;
using tailgate::linux_frontend::UniqueFd;
using tailgate::linux_frontend::WriteResolver;
using tailgate::linux_frontend::event::EventHandle;
using tailgate::linux_frontend::event::EventInterest;
using tailgate::linux_frontend::event::EventRegistry;
using Ipv4Prefix = tailgate::net::packet::Ipv4Prefix;
using TailPeer = tailgate::types::netmap::PeerConfig;
using tailgate::base::EventReadiness;
using tailgate::base::HasReadiness;

constexpr std::size_t MaximumPacketsPerDescriptorCycle = 16;
constexpr std::size_t MaximumPendingBytesPerPeer = 4U * 1024U * 1024U;
constexpr auto PendingDnsTimeout = std::chrono::seconds(10);
constexpr auto RelayHeartbeatInterval = std::chrono::seconds(20);
constexpr std::size_t RelayPacketBufferSize = 4096;
constexpr int TailgateMtu = 1280;

struct RelayEndpoint
{
    std::string Host;
    std::string ConnectAddress;
    std::string Port;
};

RelayEndpoint ParseRelayEndpoint(const std::string& url)
{
    constexpr std::string_view prefix = "https://";
    if (url.rfind(prefix, 0) != 0)
    {
        throw std::runtime_error("tailgate server URL must use https://");
    }
    std::string authority = url.substr(prefix.size());
    const std::size_t slash = authority.find('/');
    if (slash != std::string::npos)
    {
        authority.resize(slash);
    }
    const std::size_t colon = authority.rfind(':');
    if (authority.empty())
    {
        throw std::runtime_error("tailgate server URL has no host");
    }
    if (colon == std::string::npos)
    {
        return RelayEndpoint{.Host = authority, .ConnectAddress = {}, .Port = "443"};
    }
    if (colon == 0 || colon + 1 == authority.size())
    {
        throw std::runtime_error("tailgate server URL has an invalid port");
    }
    return RelayEndpoint{.Host = authority.substr(0, colon),
                         .ConnectAddress = {},
                         .Port = authority.substr(colon + 1)};
}

RelayEndpoint ResolveRelayEndpoint(RelayEndpoint endpoint,
                                   const std::string& interfaceName,
                                   tailgate::types::nettype::TcpSocketFactory& socketFactory,
                                   std::size_t addressAttempt)
{
    constexpr const char* CloudflareAddress = "1.1.1.1";
    constexpr const char* CloudflareTlsName = "cloudflare-dns.com";
    constexpr const char* DnsOverTlsPort = "853";
    constexpr std::size_t MaximumCanonicalQueries = 8;
    if (tailgate::net::Ipv4Address::TryParse(endpoint.Host))
    {
        endpoint.ConnectAddress = endpoint.Host;
        return endpoint;
    }
    std::unique_ptr<tailgate::types::nettype::TcpSocket> dnsTransport =
        socketFactory.OpenTcpSocket(tailgate::types::nettype::TcpSocketOptions{
            .ConnectAddress = CloudflareAddress,
            .Service = DnsOverTlsPort,
            .NetworkInterface = interfaceName,
            .TlsServerName = CloudflareTlsName,
            .IoTimeout = std::chrono::seconds(15),
            .ConnectTimeout = std::nullopt,
            .ReadinessToken = {},
            .AllowTls13 = true,
            .NonBlockingAfterConnect = false,
        });
    const tailgate::net::dns::DnsTarget target = tailgate::net::dns::ResolveDnsOverTlsTarget(
        *dnsTransport, endpoint.Host, addressAttempt, MaximumCanonicalQueries);
    endpoint.Host = target.ValidationName;
    endpoint.ConnectAddress = target.ConnectAddress;
    tailgate::base::Log(
        tailgate::base::LogLevel::Info,
        "dns",
        std::format("relay resolution name={} address={}", endpoint.Host, endpoint.ConnectAddress));
    return endpoint;
}

void RunRelayConnectionImpl(const std::string& url,
                            const std::string& authKey,
                            const std::string& followupUrl,
                            const tailgate::control::client::HostInfo& host,
                            const tailgate::crypto::Bytes32& machinePrivateKey,
                            const tailgate::crypto::Bytes32& nodePrivateKey,
                            const tailgate::crypto::Bytes32& discoPrivateKey,
                            bool acceptDns,
                            const std::string& exitNode,
                            tailgate::linux_frontend::DaemonStatus& status,
                            int& readyFd,
                            std::size_t addressAttempt,
                            tailgate::linux_frontend::Registration& registrationHandler,
                            const std::string& reauthorizationKey)
{
    const std::string underlayInterface = DefaultRouteInterface();
    tailgate::di::Injector networkInjector;
    tailgate::linux_frontend::InstallBindings(networkInjector);
    tailgate::types::nettype::TcpSocketFactory& tcpSocketFactory =
        networkInjector.create<tailgate::types::nettype::TcpSocketFactory&>();
    const RelayEndpoint endpoint = ResolveRelayEndpoint(
        ParseRelayEndpoint(url), underlayInterface, tcpSocketFactory, addressAttempt);
    const std::vector<std::string> originalResolvers = ReadResolverAddresses();
    tailgate::control::client::ConnectionFactory& controlConnectionFactory =
        networkInjector.create<tailgate::control::client::ConnectionFactory&>();
    std::unique_ptr<tailgate::control::client::Connection> ownedControl =
        controlConnectionFactory.CreateConnection(tailgate::control::client::SessionOptions{
            .Host = host,
            .MachinePrivateKey = machinePrivateKey,
            .NodePrivateKey = nodePrivateKey,
            .ExternalNodePublicKey = std::nullopt,
            .NetworkInterface = underlayInterface,
            .ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::RelayControl).Token(),
        });
    tailgate::control::client::Connection& control = *ownedControl;
    control.SetDiscoPrivateKey(discoPrivateKey);
    const tailgate::control::client::RegistrationOptions registrationOptions{
        .InitialFollowupUrl = followupUrl,
        .ReauthorizationKey = reauthorizationKey,
        .Handler = &registrationHandler,
    };
    tailgate::control::client::RegistrationResult registration =
        control.RegisterUntilAuthorized(authKey, registrationOptions);
    if (!registration.Network)
    {
        throw std::runtime_error("control registration completed without a network map");
    }
    tailgate::types::netmap::NetworkConfig config = std::move(*registration.Network);
    registrationHandler.Accepted();
    control.UpdateHostInfo(config.DerpRegion());
    if (!registration.NetworkMapStreaming)
    {
        control.SetPreferredDerp(config.DerpRegion());
    }
    std::string effectiveExitNode = exitNode;
    if (!effectiveExitNode.empty() && !config.FindExitNode(effectiveExitNode, true))
    {
        tailgate::base::Log(tailgate::base::LogLevel::Warning,
                            "control",
                            "exit node not found or offline; continuing without it: " +
                                effectiveExitNode);
        effectiveExitNode.clear();
    }
    tailgate::hosted::Client& hostedClient = networkInjector.create<tailgate::hosted::Client&>();
    tailgate::hosted::Dns& hostedDns = networkInjector.create<tailgate::hosted::Dns&>();
    tailgate::wgengine::ping::Tracker& pingTracker =
        networkInjector.create<tailgate::wgengine::ping::Tracker&>();
    pingTracker.Reset();
    tailgate::hosted::Connection& hostedConnection =
        networkInjector.create<tailgate::hosted::Connection&>();
    tailgate::hosted::ConnectionResult hosted =
        hostedConnection.Connect(
            tailgate::hosted::ConnectionOptions{
                .Socket =
                    tailgate::types::nettype::TcpSocketOptions{
                        .ConnectAddress = endpoint.ConnectAddress,
                        .Service = endpoint.Port,
                        .NetworkInterface = underlayInterface,
                        .TlsServerName = endpoint.Host,
                        .IoTimeout = std::chrono::seconds(
                            tailgate::linux_frontend::impl::TcpStream::ControlIoTimeoutSeconds),
                        .ConnectTimeout = std::nullopt,
                        .ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::Control).Token(),
                        .AllowTls13 = true,
                        .NonBlockingAfterConnect = true,
                    },
                .HttpHost = std::format("{}:{}", endpoint.Host, endpoint.Port),
                .Hostname = host.Hostname(),
                .OperatingSystem = host.OperatingSystem(),
                .OperatingSystemVersion = host.OperatingSystemVersion(),
                .Client =
                    tailgate::hosted::ClientConfig{
                        .NodePrivateKey = nodePrivateKey,
                        .NodePublicKey = control.NodePublicKey(),
                        .DiscoPrivateKey = discoPrivateKey,
                        .Network = config,
                        .ExitNode = effectiveExitNode,
                    },
            });
    tailgate::types::nettype::TcpSocket& tls = *hosted.Stream;
    tailgate::hosted::Decoder decoder = std::move(hosted.FrameDecoder);
    const std::optional<tailgate::linux_frontend::RelaySessionState> savedSession =
        tailgate::linux_frontend::ReadRelaySession();
    const auto hasKey = [](const tailgate::crypto::Bytes32& key)
    {
        return std::any_of(key.begin(),
                           key.end(),
                           [](std::uint8_t byte)
                           {
                               return byte != 0;
                           });
    };
    if (savedSession && savedSession->ServerUrl == url && hasKey(savedSession->RelayPublicKey) &&
        savedSession->RelayPublicKey != hosted.RelayPublicKey)
    {
        // The HTTPS certificate authenticates the server, so a rotated relay node key (for
        // example after the relay recreated its identity) is only worth a notice.
        tailgate::base::Log(tailgate::base::LogLevel::Info,
                            "relay",
                            "tailgate server node key changed; trusting the TLS certificate");
    }

    const tailgate::hosted::Session session = std::move(hosted.RelaySession);
    std::string relayHostName = session.RelayHostName();
    tailgate::linux_frontend::WriteRelaySession(tailgate::linux_frontend::RelaySessionState{
        .ServerUrl = url, .Tailnet = session.Tailnet(), .RelayPublicKey = hosted.RelayPublicKey});
    if (config.Domain() != session.Tailnet())
    {
        throw std::runtime_error("tailgate session and network map tailnets differ");
    }
    bool relayHostStateKnown = false;
    bool relayHostOnline = false;
    const auto updateRelayHostState = [&](const tailgate::types::netmap::NetworkConfig& next)
    {
        const auto relayHost = std::find_if(next.Peers().begin(),
                                            next.Peers().end(),
                                            [&](const TailPeer& peer)
                                            {
                                                return peer.Address() == session.RelayHostAddress();
                                            });
        const bool online = relayHost != next.Peers().end() && relayHost->Online();
        if (relayHost != next.Peers().end())
        {
            relayHostName = relayHost->DisplayName();
        }
        if (!relayHostStateKnown || online != relayHostOnline)
        {
            if (!online)
            {
                tailgate::base::Log(
                    tailgate::base::LogLevel::Warning,
                    "control",
                    std::format("tailgate server not found or offline; continuing through "
                                "existing connection: {}",
                                relayHostName));
            }
            else if (relayHostStateKnown)
            {
                tailgate::base::Log(tailgate::base::LogLevel::Info,
                                    "control",
                                    "tailgate server is online again: " + relayHostName);
            }
            relayHostStateKnown = true;
            relayHostOnline = online;
        }
    };
    updateRelayHostState(config);
    tailgate::disco::Disco& disco = hostedClient.Disco();
    tailgate::hosted::ClientSession& hostedSession =
        networkInjector.create<tailgate::hosted::ClientSession&>();
    tailgate::wgengine::Session& networkSession =
        networkInjector.create<tailgate::wgengine::Session&>();
    networkSession.SetControlConnection(std::move(ownedControl));

    const std::string interfaceName = "tailgate0";
    if (!hostedSession.OpenPacketDevice(tailgate::wgengine::tstun::DeviceOptions{
            .Name = interfaceName,
            .ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::Tun).Token(),
        }))
    {
        throw std::runtime_error("failed to open packet device");
    }
    SetInterfaceAddress(interfaceName, config.SelfAddress());
    const std::string selfIpv6 = config.FirstIpv6Address();
    if (!selfIpv6.empty())
    {
        SetInterfaceIpv6Address(interfaceName, selfIpv6);
    }
    SetInterfaceMtu(interfaceName, TailgateMtu);
    tailgate::wgengine::router::Config routerConfig =
        tailgate::wgengine::router::Config::Build(config,
                                                  tailgate::wgengine::router::ConfigOptions{
                                                      .AdditionalRoutes = {},
                                                      .RouteAllTraffic = !effectiveExitNode.empty(),
                                                  });
    for (const Ipv4Prefix& route : routerConfig.Routes())
    {
        AddRoute(interfaceName, route);
    }
    if (acceptDns && !config.DnsResolver().empty())
    {
        WriteResolver("127.0.0.1", config.DnsDomains());
    }

    const auto applyNetworkMap = [&](const tailgate::types::netmap::NetworkConfig& next)
    {
        if (next.Domain() != session.Tailnet() || next.SelfAddress() != config.SelfAddress())
        {
            throw std::runtime_error("tailgate relay changed the client identity");
        }
        config = next;
        const bool wasExitNodeEnabled = !effectiveExitNode.empty();
        const bool exitNodeAvailable = !exitNode.empty() && config.FindExitNode(exitNode, true);
        if (wasExitNodeEnabled && !exitNodeAvailable)
        {
            tailgate::base::Log(tailgate::base::LogLevel::Warning,
                                "control",
                                "configured exit node became unavailable; disabling it: " +
                                    effectiveExitNode);
            effectiveExitNode.clear();
        }
        else if (!wasExitNodeEnabled && exitNodeAvailable)
        {
            effectiveExitNode = exitNode;
            tailgate::base::Log(tailgate::base::LogLevel::Info,
                                "control",
                                "configured exit node is available; enabling it: " +
                                    effectiveExitNode);
        }
        const tailgate::wgengine::router::Config nextRouterConfig =
            tailgate::wgengine::router::Config::Build(
                config,
                tailgate::wgengine::router::ConfigOptions{
                    .AdditionalRoutes = {},
                    .RouteAllTraffic = !effectiveExitNode.empty(),
                });
        ApplyRouteChanges(interfaceName, routerConfig, nextRouterConfig);
        routerConfig = nextRouterConfig;
        std::vector<std::uint8_t> relayUpdate =
            hostedClient.UpdateNetworkMap(config, effectiveExitNode);
        updateRelayHostState(config);
        status.BackendState = "Running";
        status.Online = true;
        status.Address = config.SelfAddress();
        status.Domain = config.Domain();
        status.Hostname = config.DisplayName();
        status.Error.clear();
        status.Peers.clear();
        for (const TailPeer& peer : config.Peers())
        {
            if (peer.Name().empty())
            {
                continue;
            }
            tailgate::linux_frontend::PeerStatus peerStatus;
            peerStatus.Address = peer.Address();
            peerStatus.Hostname = peer.DisplayName();
            peerStatus.OperatingSystem = peer.OperatingSystem();
            peerStatus.Relay = peer.DerpCode();
            peerStatus.Online = peer.Online();
            peerStatus.ExitNodeOption = peer.ExitNodeOption();
            status.Peers.push_back(std::move(peerStatus));
        }
        if (acceptDns && !config.DnsResolver().empty())
        {
            WriteResolver("127.0.0.1", config.DnsDomains());
        }
        tailgate::linux_frontend::WriteDaemonStatus(status);
        return relayUpdate;
    };
    (void)applyNetworkMap(config);
    control.StartStreaming();
    EventRegistry& eventRegistry = networkInjector.create<EventRegistry&>();
    UniqueFd pingServer = tailgate::linux_frontend::OpenPingServer();
    UniqueFd localDns = acceptDns ? OpenLocalDnsSocket() : UniqueFd{};
    UniqueFd upstreamDns = OpenUdpSocket(underlayInterface);
    EventHandle pingEvent = eventRegistry.Register(
        pingServer.Fd, EventInterest::Readable, DataplaneEvent(DataplaneEvent::Kind::Ping).Token());
    EventHandle localDnsEvent;
    if (localDns.Fd >= 0)
    {
        localDnsEvent =
            eventRegistry.Register(localDns.Fd,
                                   EventInterest::Readable,
                                   DataplaneEvent(DataplaneEvent::Kind::LocalDns).Token());
    }
    EventHandle upstreamDnsEvent =
        eventRegistry.Register(upstreamDns.Fd,
                               EventInterest::Readable,
                               DataplaneEvent(DataplaneEvent::Kind::UpstreamDns).Token());
    std::deque<std::vector<std::uint8_t>> socketOutput;
    std::size_t socketOffset = 0;
    std::size_t socketOutputBytes = 0;

    struct PendingPingClient
    {
        std::uint64_t RequestId = 0;
        sockaddr_un Client{};
        socklen_t ClientLength = 0;
    };

    std::vector<PendingPingClient> pendingPingClients;
    std::uint64_t nextPingRequestId = 1;
    auto nextHeartbeat = std::chrono::steady_clock::now() + RelayHeartbeatInterval;
    auto nextDiscoProbe = std::chrono::steady_clock::now();

    struct PendingRelayDns
    {
        sockaddr_in Client{};
        std::uint32_t Resolver = 0;
        std::uint16_t Id = 0;
        std::uint16_t SourcePort = 0;
        std::chrono::steady_clock::time_point Started{};
    };

    std::vector<PendingRelayDns> pendingDns;
    const auto updateSocketEvents = [&]()
    {
        const EventInterest interest = socketOutput.empty() && !tls.ReadNeedsWrite()
                                           ? EventInterest::Readable
                                           : EventInterest::Readable | EventInterest::Writable;
        tls.SetWriteInterest(interest == (EventInterest::Readable | EventInterest::Writable));
    };
    const auto queueEncoded = [&](std::vector<std::uint8_t> encoded)
    {
        if (encoded.empty())
        {
            return;
        }
        socketOutputBytes += encoded.size();
        if (socketOutputBytes > MaximumPendingBytesPerPeer)
        {
            throw std::runtime_error("relay socket output queue limit exceeded");
        }
        socketOutput.push_back(std::move(encoded));
        updateSocketEvents();
    };
    const auto queueFrame = [&](tailgate::hosted::Frame frame)
    {
        queueEncoded(frame.Encode());
    };
    const auto flushSocketOutput = [&]()
    {
        if (socketOutput.empty() || tls.ReadNeedsWrite())
        {
            return;
        }
        const std::vector<std::uint8_t>& output = socketOutput.front();
        const std::optional<std::size_t> written =
            tls.TryWriteSome(output.data() + socketOffset, output.size() - socketOffset);
        if (written)
        {
            socketOffset += *written;
            if (socketOffset == output.size())
            {
                socketOutputBytes -= output.size();
                socketOutput.pop_front();
                socketOffset = 0;
            }
        }
        updateSocketEvents();
    };
    const auto notifyReady = [&]()
    {
        if (readyFd >= 0)
        {
            const char ready = '1';
            (void)write(readyFd, &ready, 1);
            close(readyFd);
            readyFd = -1;
        }
    };
    const auto queueDisco = [&](const tailgate::crypto::Bytes32& peer,
                                std::vector<std::uint8_t> payload,
                                std::uint32_t address = 0,
                                std::uint16_t port = 0)
    {
        queueFrame(tailgate::hosted::Frame(
            tailgate::hosted::MessageType::ClientPacket,
            tailgate::hosted::ProtocolCodec::EncodePeerPacket(tailgate::hosted::PeerPacket(
                peer, std::move(payload), false, true, address, port))));
    };
    const auto completePing = [&](const tailgate::wgengine::ping::Result& result)
    {
        const auto pending =
            std::ranges::find_if(pendingPingClients,
                                 [&](const PendingPingClient& candidate)
                                 {
                                     return candidate.RequestId == result.RequestId;
                                 });
        if (pending == pendingPingClients.end())
        {
            return;
        }
        tailgate::linux_frontend::PingResponse response{};
        response.Responded = result.Responded;
        response.LatencyMilliseconds = static_cast<int>(
            std::chrono::duration_cast<std::chrono::milliseconds>(result.Latency).count());
        response.NodeName = result.PeerName;
        response.NodeAddress = result.PeerAddress;
        response.Relay = result.Relay;
        response.Endpoint = std::format("tailgate({})", relayHostName);
        response.PeerApiPort = result.PeerApiPort;
        tailgate::linux_frontend::SendPingResponse(
            pingServer.Fd, pending->Client, pending->ClientLength, response);
        pendingPingClients.erase(pending);
    };
    const auto handlePlaintext = [&](std::vector<std::uint8_t> packet)
    {
        const auto dns = std::find_if(
            pendingDns.begin(),
            pendingDns.end(),
            [&](const PendingRelayDns& pending)
            {
                const auto payload = tailgate::net::packet::Ipv4UdpDatagram::ExtractPayload(
                    packet,
                    pending.Resolver,
                    tailgate::net::Ipv4Address::Parse(config.SelfAddress()).HostOrder(),
                    53,
                    pending.SourcePort);
                return payload && payload->size() >= 2 &&
                       (((static_cast<std::uint16_t>((*payload)[0]) << 8U) | (*payload)[1]) ==
                        pending.Id);
            });
        if (dns != pendingDns.end())
        {
            const auto payload = tailgate::net::packet::Ipv4UdpDatagram::ExtractPayload(
                packet,
                dns->Resolver,
                tailgate::net::Ipv4Address::Parse(config.SelfAddress()).HostOrder(),
                53,
                dns->SourcePort);
            SendUdp(localDns.Fd, dns->Client, *payload);
            pendingDns.erase(dns);
            return;
        }
        if (const auto pong = tailgate::net::packet::TsmpPacket::BuildPong(packet, 0))
        {
            queueEncoded(hostedClient.Encapsulate(*pong));
            return;
        }
        if (const auto pong = tailgate::net::packet::TsmpPacket::ParsePong(packet))
        {
            const std::optional<tailgate::wgengine::ping::Result> result = pingTracker.CompleteTsmp(
                pong->Token(), pong->PeerApiPort(), std::chrono::steady_clock::now());
            if (result)
            {
                completePing(*result);
            }
            return;
        }
        const tailgate::hosted::PacketDeviceStatus written =
            hostedSession.WritePacketDevice(std::move(packet));
        if (written != tailgate::hosted::PacketDeviceStatus::Ready)
        {
            throw std::runtime_error("packet device rejected a hosted packet");
        }
    };
    queueEncoded(hostedClient.BuildKeepAlive());
    flushSocketOutput();
    while (!Lifecycle::Stopping() && !Lifecycle::Reloading())
    {
        constexpr std::size_t MaximumRelayEvents = 8;
        tailgate::wgengine::SessionWaitResult waitResult = networkSession.Wait(
            MaximumRelayEvents, MaximumPacketsPerDescriptorCycle, RelayPacketBufferSize);
        if (waitResult.Status == tailgate::base::EventWaitStatus::Woken)
        {
            continue;
        }
        for (const tailgate::types::netmap::NetworkConfig& update : waitResult.NetworkMaps)
        {
            queueEncoded(applyNetworkMap(update));
        }
        for (const tailgate::base::Event& ready : waitResult.PlatformEvents)
        {
            const DataplaneEvent event = DataplaneEvent::FromValue(ready.Token.Value);
            if (event.Type() == DataplaneEvent::Kind::RelayControl)
            {
                continue;
            }
            if (HasReadiness(ready.Readiness, EventReadiness::Error) ||
                HasReadiness(ready.Readiness, EventReadiness::Closed))
            {
                throw std::runtime_error("tailgate relay transport closed");
            }
            if (event.Type() == DataplaneEvent::Kind::Tun)
            {
                if (HasReadiness(ready.Readiness, EventReadiness::Writable) &&
                    hostedSession.FlushPacketDevice() !=
                        tailgate::hosted::PacketDeviceStatus::Ready)
                {
                    throw std::runtime_error("packet device closed during write");
                }
                if (HasReadiness(ready.Readiness, EventReadiness::Readable))
                {
                    tailgate::hosted::ClientSessionProcessResult processed =
                        hostedSession.ProcessPacketDevice(MaximumPacketsPerDescriptorCycle,
                                                          RelayPacketBufferSize);
                    if (processed.DeviceStatus != tailgate::hosted::PacketDeviceStatus::Ready)
                    {
                        throw std::runtime_error("packet device closed during read");
                    }
                    queueEncoded(std::move(processed.RemoteOutput));
                }
                continue;
            }
            if (event.Type() == DataplaneEvent::Kind::Ping &&
                HasReadiness(ready.Readiness, EventReadiness::Readable))
            {
                tailgate::linux_frontend::PingRequest pingRequest{};
                sockaddr_un client{};
                socklen_t clientLength = sizeof(client);
                if (tailgate::linux_frontend::ReceivePingRequest(
                        pingServer.Fd, pingRequest, client, clientLength))
                {
                    const std::uint64_t requestId = nextPingRequestId++;
                    tailgate::wgengine::ping::StartResult started = pingTracker.Start(
                        tailgate::wgengine::ping::Request{
                            .Id = requestId,
                            .Target = pingRequest.Target,
                            .PingMode = pingRequest.Tsmp ? tailgate::wgengine::ping::Mode::Tsmp
                                                         : tailgate::wgengine::ping::Mode::Disco,
                            .Timeout =
                                std::chrono::seconds(std::max(1, pingRequest.TimeoutSeconds)),
                            .Relay = relayHostName,
                        },
                        config,
                        disco,
                        std::chrono::steady_clock::now());
                    if (started.Status != tailgate::wgengine::ping::StartStatus::Ready ||
                        !started.Outbound)
                    {
                        tailgate::linux_frontend::PingResponse response{};
                        tailgate::linux_frontend::SendPingResponse(
                            pingServer.Fd, client, clientLength, response);
                    }
                    else
                    {
                        pendingPingClients.push_back(PendingPingClient{
                            .RequestId = requestId,
                            .Client = client,
                            .ClientLength = clientLength,
                        });
                        if (started.Outbound->Disco)
                        {
                            queueDisco(started.Outbound->Peer,
                                       std::move(started.Outbound->Payload));
                        }
                        else
                        {
                            queueEncoded(
                                hostedClient.Encapsulate(std::move(started.Outbound->Payload)));
                        }
                    }
                }
            }
            if (event.Type() == DataplaneEvent::Kind::LocalDns &&
                HasReadiness(ready.Readiness, EventReadiness::Readable))
            {
                sockaddr_in client{};
                std::vector<std::uint8_t> dnsPayload = ReceiveUdp(localDns.Fd, &client);
                if (dnsPayload.size() >= 2)
                {
                    const std::uint16_t dnsId =
                        (static_cast<std::uint16_t>(dnsPayload[0]) << 8U) | dnsPayload[1];
                    const std::uint16_t sourcePort = ntohs(client.sin_port);
                    const std::optional<tailgate::net::dns::ResolverSelection> selection =
                        tailgate::net::dns::SelectResolver(dnsPayload,
                                                           config.DnsResolver(),
                                                           config.DnsRoutes(),
                                                           originalResolvers);
                    if (!selection)
                    {
                        throw std::runtime_error("no DNS resolver is available");
                    }
                    const std::uint32_t resolver =
                        tailgate::net::Ipv4Address::Parse(selection->Address).HostOrder();
                    pendingDns.erase(std::remove_if(pendingDns.begin(),
                                                    pendingDns.end(),
                                                    [&](const PendingRelayDns& pending)
                                                    {
                                                        return pending.Id == dnsId &&
                                                               pending.SourcePort == sourcePort;
                                                    }),
                                     pendingDns.end());
                    pendingDns.push_back(
                        PendingRelayDns{.Client = client,
                                        .Resolver = resolver,
                                        .Id = dnsId,
                                        .SourcePort = sourcePort,
                                        .Started = std::chrono::steady_clock::now()});
                    if (selection->RouteMatched)
                    {
                        const std::vector<std::uint8_t> packet =
                            tailgate::net::packet::Ipv4UdpDatagram::Build(
                                tailgate::net::Ipv4Address::Parse(config.SelfAddress()).HostOrder(),
                                resolver,
                                sourcePort,
                                53,
                                dnsPayload);
                        tailgate::hosted::DnsResult hostedQuery =
                            hostedDns.ProcessQuery(packet, config);
                        if (hostedQuery.Status == tailgate::hosted::DnsStatus::Complete)
                        {
                            queueFrame(std::move(*hostedQuery.RemoteFrame));
                        }
                        else
                        {
                            queueEncoded(hostedClient.Encapsulate(packet));
                        }
                    }
                    else
                    {
                        sockaddr_in destination{};
                        destination.sin_family = AF_INET;
                        destination.sin_addr.s_addr = htonl(resolver);
                        destination.sin_port = htons(53);
                        SendUdp(upstreamDns.Fd, destination, dnsPayload);
                    }
                }
            }
            if (event.Type() == DataplaneEvent::Kind::UpstreamDns &&
                HasReadiness(ready.Readiness, EventReadiness::Readable))
            {
                sockaddr_in source{};
                const std::vector<std::uint8_t> response = ReceiveUdp(upstreamDns.Fd, &source);
                if (response.size() >= 2)
                {
                    const std::uint16_t id =
                        (static_cast<std::uint16_t>(response[0]) << 8U) | response[1];
                    const auto pending =
                        std::find_if(pendingDns.begin(),
                                     pendingDns.end(),
                                     [&](const PendingRelayDns& candidate)
                                     {
                                         return candidate.Id == id &&
                                                candidate.Resolver == ntohl(source.sin_addr.s_addr);
                                     });
                    if (pending != pendingDns.end())
                    {
                        SendUdp(localDns.Fd, pending->Client, response);
                        pendingDns.erase(pending);
                    }
                }
            }
            if (event.Type() == DataplaneEvent::Kind::Control &&
                (HasReadiness(ready.Readiness, EventReadiness::Readable) ||
                 (HasReadiness(ready.Readiness, EventReadiness::Writable) &&
                  tls.ReadNeedsWrite())) &&
                !(tls.WriteNeedsRead() && !socketOutput.empty()))
            {
                tailgate::hosted::DecoderReadResult relayInput =
                    decoder.ReadAvailable(tls, 16U * 1024U);
                if (relayInput.Status == tailgate::hosted::DecoderReadStatus::Closed)
                {
                    throw std::runtime_error("tailgate relay closed");
                }
                for (tailgate::hosted::Frame& frame : relayInput.Frames)
                {
                    tailgate::hosted::DnsResult dnsResult =
                        hostedDns.ProcessResponse(frame, config);
                    if (dnsResult.Status == tailgate::hosted::DnsStatus::Invalid)
                    {
                        throw std::runtime_error("tailgate relay returned an invalid DNS response");
                    }
                    if (dnsResult.Status == tailgate::hosted::DnsStatus::Complete)
                    {
                        handlePlaintext(std::move(*dnsResult.LocalPacket));
                        continue;
                    }
                    tailgate::hosted::ClientProcessResult processed = hostedClient.Process(frame);
                    if (processed.NetworkMapChanged)
                    {
                        if (hostedClient.Network().SelfAddress() != config.SelfAddress())
                        {
                            throw std::runtime_error("tailgate relay changed the client identity");
                        }
                        (void)applyNetworkMap(hostedClient.Network());
                    }
                    if (processed.DataPathReady)
                    {
                        notifyReady();
                    }
                    if (processed.Pong)
                    {
                        const std::optional<tailgate::wgengine::ping::Result> result =
                            pingTracker.CompleteDisco(processed.Pong->Packet.Peer(),
                                                      processed.Pong->Message.Transaction,
                                                      0,
                                                      std::chrono::steady_clock::now());
                        if (result)
                        {
                            completePing(*result);
                        }
                    }
                    queueEncoded(std::move(processed.RemoteOutput));
                    for (std::vector<std::uint8_t>& plaintext : processed.LocalPackets)
                    {
                        handlePlaintext(std::move(plaintext));
                    }
                    if (frame.Type() == tailgate::hosted::MessageType::Heartbeat)
                    {
                        nextHeartbeat = std::chrono::steady_clock::now() + RelayHeartbeatInterval;
                    }
                }
                updateSocketEvents();
            }
            if (event.Type() == DataplaneEvent::Kind::Control && !socketOutput.empty() &&
                !tls.ReadNeedsWrite() &&
                (HasReadiness(ready.Readiness, EventReadiness::Writable) ||
                 (HasReadiness(ready.Readiness, EventReadiness::Readable) && tls.WriteNeedsRead())))
            {
                flushSocketOutput();
            }
        }
        if (waitResult.MaintenanceDue)
        {
            const auto now = std::chrono::steady_clock::now();
            if (now >= nextHeartbeat)
            {
                queueEncoded(hostedClient.BuildKeepAlive());
                nextHeartbeat = now + RelayHeartbeatInterval;
            }
            else
            {
                queueEncoded(hostedClient.UpdateTimers());
            }
            if (now >= nextDiscoProbe)
            {
                queueEncoded(hostedClient.ProbePeers());
                nextDiscoProbe =
                    now + tailgate::wgengine::magicsock::PeerPathState::DirectProbeInterval;
            }
            for (const tailgate::wgengine::ping::Result& expired : pingTracker.Expire(now))
            {
                completePing(expired);
            }
            pendingDns.erase(std::remove_if(pendingDns.begin(),
                                            pendingDns.end(),
                                            [&](const PendingRelayDns& pending)
                                            {
                                                return now - pending.Started >= PendingDnsTimeout;
                                            }),
                             pendingDns.end());
        }
    }
    if (Lifecycle::Stopping())
    {
        tls.SetNonBlocking(false);
        tailgate::hosted::Frame(tailgate::hosted::MessageType::Shutdown, {}).Write(tls);
    }
    hostedSession.ClosePacketDevice();
    unlink(tailgate::linux_frontend::PingSocketPath().c_str());
}

} // namespace

namespace tailgate::linux_frontend
{

void RunHostedClient(const std::string& url,
                     const std::string& authKey,
                     const std::string& followupUrl,
                     const tailgate::control::client::HostInfo& host,
                     const tailgate::crypto::Bytes32& machinePrivateKey,
                     const tailgate::crypto::Bytes32& nodePrivateKey,
                     const tailgate::crypto::Bytes32& discoPrivateKey,
                     bool acceptDns,
                     const std::string& exitNode,
                     DaemonStatus& status,
                     int& readyFd,
                     std::size_t addressAttempt,
                     Registration& registration,
                     const std::string& reauthorizationKey)
{
    RunRelayConnectionImpl(url,
                           authKey,
                           followupUrl,
                           host,
                           machinePrivateKey,
                           nodePrivateKey,
                           discoPrivateKey,
                           acceptDns,
                           exitNode,
                           status,
                           readyFd,
                           addressAttempt,
                           registration,
                           reauthorizationKey);
}

} // namespace tailgate::linux_frontend
