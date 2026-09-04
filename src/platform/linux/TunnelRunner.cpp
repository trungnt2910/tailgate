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
#include <limits>
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
#include <tailgate/hosted/Connection.h>
#include <tailgate/hosted/DiscoProbes.h>
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
#include <tailgate/wgengine/Engine.h>
#include <tailgate/wgengine/Session.h>
#include <tailgate/wgengine/magicsock/Connection.h>
#include <tailgate/wgengine/magicsock/PeerPathState.h>
#include <tailgate/wgengine/router/Config.h>
#include <tailgate/wgengine/wireguard/Router.h>

#include "DI.h"
#include "DataplaneEvents.h"
#include "Files.h"
#include "HostedConnectionRegistry.h"
#include "HostedDerpRouteTable.h"
#include "Network.h"
#include "PeerApiServer.h"
#include "PingIpc.h"
#include "QrCode.h"
#include "RelayServer.h"
#include "State.h"
#include "StatusWriter.h"
#include "UniqueFd.h"
#include "event/EventRegistry.h"

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

constexpr int FunnelPeerApiPort = 41112;
constexpr std::size_t MaximumPacketsPerDescriptorCycle = 16;
constexpr auto PendingDnsTimeout = std::chrono::seconds(10);
constexpr std::size_t RelayPacketBufferSize = 4096;
constexpr auto StatusRefreshInterval = std::chrono::seconds(10);
constexpr int TailgateMtu = 1280;

struct PeerRuntime
{
    TailPeer Config;
    tailgate::crypto::Bytes32 PublicKey{};
    tailgate::crypto::Bytes32 DiscoPublicKey{};
    bool HasDiscoKey = false;
    std::uint64_t TxBytes = 0;
    std::uint64_t RxBytes = 0;
};

tailgate::net::Endpoint ToEndpoint(const sockaddr_in& endpoint)
{
    return tailgate::net::Endpoint(
        tailgate::net::Ipv4Address::FromHostOrder(ntohl(endpoint.sin_addr.s_addr)),
        ntohs(endpoint.sin_port));
}

sockaddr_in ToSockaddr(const tailgate::net::Endpoint& endpoint)
{
    sockaddr_in result{};
    result.sin_family = AF_INET;
    result.sin_addr.s_addr = htonl(endpoint.Address().HostOrder());
    result.sin_port = htons(endpoint.Port());
    return result;
}

struct DerpRuntime
{
    int Region = 0;
    std::string Host;
    tailgate::wgengine::DerpConnectionId Connection = 0;
    tailgate::hosted::DerpRoute Route;
};

constexpr auto DataplaneSlowSection = std::chrono::milliseconds(50);
constexpr auto PingRetryInterval = std::chrono::seconds(1);

template <typename Callback>
void TimedSection(const char* name, Callback&& callback)
{
    const auto started = std::chrono::steady_clock::now();
    callback();
    const auto elapsed = std::chrono::steady_clock::now() - started;
    if (elapsed >= DataplaneSlowSection)
    {
        tailgate::base::Log(
            tailgate::base::LogLevel::Warning,
            "dataplane",
            std::format("{} took {}ms",
                        name,
                        std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()));
    }
}

std::optional<std::string> Ipv6DestinationText(const std::vector<std::uint8_t>& packet)
{
    constexpr std::size_t ipv6HeaderSize = 40;
    constexpr std::size_t ipv6DestinationOffset = 24;
    constexpr std::uint8_t ipv6Version = 6;
    if (packet.size() < ipv6HeaderSize || (packet[0] >> 4U) != ipv6Version)
    {
        return std::nullopt;
    }
    std::vector<char> text(INET6_ADDRSTRLEN);
    if (inet_ntop(AF_INET6,
                  packet.data() + ipv6DestinationOffset,
                  text.data(),
                  static_cast<socklen_t>(text.size())) == nullptr)
    {
        return std::nullopt;
    }
    return std::string(text.data());
}

std::optional<std::string> Ipv6SourceText(const std::vector<std::uint8_t>& packet)
{
    constexpr std::size_t ipv6HeaderSize = 40;
    constexpr std::size_t ipv6SourceOffset = 8;
    constexpr std::uint8_t ipv6Version = 6;
    if (packet.size() < ipv6HeaderSize || (packet[0] >> 4U) != ipv6Version)
    {
        return std::nullopt;
    }
    std::vector<char> text(INET6_ADDRSTRLEN);
    if (inet_ntop(AF_INET6,
                  packet.data() + ipv6SourceOffset,
                  text.data(),
                  static_cast<socklen_t>(text.size())) == nullptr)
    {
        return std::nullopt;
    }
    return std::string(text.data());
}

std::optional<std::string> TcpPortSummary(const std::vector<std::uint8_t>& packet)
{
    constexpr std::size_t ipv6HeaderSize = 40;
    constexpr std::size_t tcpPortsSize = 4;
    constexpr std::size_t ipv6NextHeaderOffset = 6;
    constexpr std::uint8_t tcpProtocol = 6;
    if (packet.size() < ipv6HeaderSize + tcpPortsSize ||
        packet[ipv6NextHeaderOffset] != tcpProtocol)
    {
        return std::nullopt;
    }
    const std::uint16_t sourcePort = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(packet[ipv6HeaderSize]) << 8U) | packet[ipv6HeaderSize + 1]);
    const std::uint16_t destinationPort =
        static_cast<std::uint16_t>((static_cast<std::uint16_t>(packet[ipv6HeaderSize + 2]) << 8U) |
                                   packet[ipv6HeaderSize + 3]);
    return std::format("{}->{}", sourcePort, destinationPort);
}

} // namespace

namespace tailgate::linux_frontend
{

void RunTunnel(
    const tailgate::crypto::Bytes32& nodePrivateKey,
    const tailgate::crypto::Bytes32& nodePublicKey,
    const tailgate::crypto::Bytes32& discoPrivateKey,
    const std::string& selfIp,
    const std::string& selfIpv6,
    const std::string& selfDnsName,
    const std::string& domain,
    const std::string& initialDnsResolver,
    const std::vector<std::string>& initialDnsDomains,
    const std::vector<std::string>& initialDnsDefaultResolvers,
    const std::vector<tailgate::types::netmap::NetworkConfig::DnsRoute>& initialDnsRoutes,
    const std::vector<TailPeer>& peerConfigs,
    int derpRegion,
    const std::string& derpHost,
    const std::string& exitNode,
    bool acceptDns,
    const tailgate::serve::FunnelConfig& funnel,
    const std::string& funnelCertificatePem,
    const std::string& funnelPrivateKeyPem,
    std::unique_ptr<tailgate::control::client::Connection> controlConnection,
    tailgate::linux_frontend::event::EventRegistry& eventRegistry,
    tailgate::wgengine::Engine& engine,
    tailgate::wgengine::Session& session,
    tailgate::wgengine::magicsock::Connection& connection,
    tailgate::derp::ConnectionFactory& derpConnectionFactory,
    tailgate::linux_frontend::HostedConnectionRegistry& hostedConnections,
    tailgate::linux_frontend::DaemonStatus& status,
    int& readyFd,
    bool configureHost,
    bool persistStatus,
    bool encryptedPacketTransport,
    int relayControlFd,
    std::function<void(const tailgate::types::netmap::NetworkConfig&)> networkMapUpdated,
    std::function<void()> dataPathReady,
    tailgate::derp::DerpClient::Authenticator derpAuthenticator)
{
    if (controlConnection)
    {
        session.SetControlConnection(std::move(controlConnection));
    }
    std::string interfaceName = "tailgate0";
    status.Domain = domain;
    if (!selfDnsName.empty())
    {
        const std::size_t dot = selfDnsName.find('.');
        status.Hostname = dot == std::string::npos ? selfDnsName : selfDnsName.substr(0, dot);
    }
    const std::string underlayInterface = DefaultRouteInterface();
    const std::uint32_t underlayAddress = InterfaceIpv4Address(underlayInterface);
    const std::optional<tailgate::net::Endpoint> sharedEndpoint = connection.LocalEndpoint();
    if (!sharedEndpoint)
    {
        throw std::runtime_error("advertised UDP transport is unavailable");
    }
    const std::vector<std::string> originalResolvers =
        configureHost ? ReadResolverAddresses() : std::vector<std::string>{};
    std::string currentDnsResolver = initialDnsResolver;
    std::vector<std::string> currentDnsDomains = initialDnsDomains;
    std::vector<std::string> currentDnsDefaultResolvers = initialDnsDefaultResolvers;
    std::vector<tailgate::types::netmap::NetworkConfig::DnsRoute> currentDnsRoutes =
        initialDnsRoutes;

    if (!engine.OpenPacketDevice(tailgate::wgengine::tstun::DeviceOptions{
            .Name = interfaceName,
            .ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::Tun).Token(),
        }))
    {
        throw std::runtime_error("failed to open packet device");
    }
    UniqueFd localDns;
    if (configureHost && acceptDns)
    {
        localDns = OpenLocalDnsSocket();
    }
    if (configureHost)
    {
        SetInterfaceAddress(interfaceName, selfIp);
        if (!selfIpv6.empty())
        {
            SetInterfaceIpv6Address(interfaceName, selfIpv6);
        }
        SetInterfaceMtu(interfaceName, TailgateMtu);
    }
    std::vector<std::unique_ptr<tailgate::linux_frontend::PeerApiServer>> peerApiServers;
    if (configureHost && tailgate::serve::IsEnabled(funnel))
    {
        const std::string funnelHost =
            !selfDnsName.empty() ? selfDnsName
                                 : (domain.empty() ? status.Hostname
                                                   : std::format("{}.{}", status.Hostname, domain));
        const std::string funnelTarget = tailgate::serve::TargetHostPort(funnelHost, funnel.Port);
        peerApiServers.push_back(
            std::make_unique<tailgate::linux_frontend::PeerApiServer>(selfIp,
                                                                      FunnelPeerApiPort,
                                                                      funnelTarget,
                                                                      funnel.LocalPort,
                                                                      funnelCertificatePem,
                                                                      funnelPrivateKeyPem));
        if (!selfIpv6.empty())
        {
            peerApiServers.push_back(
                std::make_unique<tailgate::linux_frontend::PeerApiServer>(selfIpv6,
                                                                          FunnelPeerApiPort,
                                                                          funnelTarget,
                                                                          funnel.LocalPort,
                                                                          funnelCertificatePem,
                                                                          funnelPrivateKeyPem));
        }
    }

    if (!encryptedPacketTransport)
    {
        session.Configure(tailgate::wgengine::SessionOptions{
            .NodePrivateKey = nodePrivateKey,
            .NodePublicKey = nodePublicKey,
            .DiscoPrivateKey = discoPrivateKey,
            .AdvertisedEndpoint = tailgate::net::Endpoint(
                tailgate::net::Ipv4Address::FromHostOrder(underlayAddress), sharedEndpoint->Port()),
            .HomeDerpRegion = derpRegion,
            .Peers = peerConfigs,
            .ExitNode = exitNode,
        });
    }
    std::deque<PeerRuntime> peers;
    auto buildPeerRuntime = [&](const TailPeer& config) -> std::optional<PeerRuntime>
    {
        std::vector<std::uint8_t> publicKeyBytes =
            tailgate::crypto::HexToBytes(config.Key().substr(8));
        if (publicKeyBytes.size() != tailgate::crypto::Bytes32{}.size())
        {
            return std::nullopt;
        }
        tailgate::crypto::Bytes32 publicKey{};
        std::copy(publicKeyBytes.begin(), publicKeyBytes.end(), publicKey.begin());
        if (encryptedPacketTransport && !connection.AddPeer(publicKey))
        {
            return std::nullopt;
        }
        PeerRuntime runtime;
        runtime.Config = config;
        runtime.PublicKey = publicKey;
        if (config.DiscoKey().rfind("discokey:", 0) == 0)
        {
            const auto discoKey = tailgate::crypto::HexToBytes(config.DiscoKey().substr(9));
            if (discoKey.size() == runtime.DiscoPublicKey.size())
            {
                std::copy(discoKey.begin(), discoKey.end(), runtime.DiscoPublicKey.begin());
                runtime.HasDiscoKey = true;
            }
        }
        return runtime;
    };
    for (const TailPeer& config : peerConfigs)
    {
        std::optional<PeerRuntime> runtime = buildPeerRuntime(config);
        if (runtime)
        {
            if (config.IngressEnabled() || config.WireIngress() || config.PeerApi4Port() != 0 ||
                config.PeerApi6Port() != 0)
            {
                tailgate::base::Log(
                    tailgate::base::LogLevel::Info,
                    "control",
                    std::format("peer advertises ingress name={} version={} ingress={} "
                                "wire-ingress={} peerapi4={} peerapi6={}",
                                config.Name(),
                                config.ClientVersion(),
                                config.IngressEnabled() ? 1 : 0,
                                config.WireIngress() ? 1 : 0,
                                config.PeerApi4Port(),
                                config.PeerApi6Port()));
            }
            peers.push_back(std::move(*runtime));
        }
    }

    if (peers.empty())
    {
        throw std::runtime_error("netmap did not contain usable IPv4 peers");
    }

    std::vector<DerpRuntime> derps;
    tailgate::linux_frontend::HostedDerpRouteTable hostedDerpRoutes;
    auto ensureDerpIndex = [&](int region, const std::string& host, bool preferred) -> std::size_t
    {
        auto found = std::find_if(derps.begin(),
                                  derps.end(),
                                  [&](const DerpRuntime& derp)
                                  {
                                      return derp.Region == region;
                                  });
        if (found != derps.end())
        {
            return static_cast<std::size_t>(found - derps.begin());
        }
        if (region <= 0 || region > std::numeric_limits<std::uint16_t>::max() || host.empty())
        {
            throw std::runtime_error("peer has no usable DERP region");
        }
        tailgate::base::Log(
            tailgate::base::LogLevel::Info,
            "derp",
            std::format(
                "connecting region={} host={}{}", region, host, preferred ? " preferred" : ""));
        const tailgate::wgengine::DerpConnectionId connectionId = session.AddDerpConnection(
            region,
            derpConnectionFactory.CreateConnection(tailgate::derp::ConnectionOptions{
                .Host = host,
                .NetworkInterface = underlayInterface,
                .PrivateKey = nodePrivateKey,
                .PublicKey = nodePublicKey,
                .Authenticator = derpAuthenticator,
                .ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::Derp,
                                                 static_cast<std::uint32_t>(derps.size()))
                                      .Token(),
                .Preferred = preferred,
            }));
        const tailgate::hosted::DerpRoute route =
            hostedDerpRoutes.Register(connectionId, static_cast<std::uint16_t>(region));
        derps.push_back(DerpRuntime{
            .Region = region,
            .Host = host,
            .Connection = connectionId,
            .Route = route,
        });
        return derps.size() - 1;
    };
    auto ensureDerp =
        [&](int region, const std::string& host, bool preferred) -> tailgate::derp::Connection&
    {
        return session.DerpConnection(derps[ensureDerpIndex(region, host, preferred)].Connection);
    };
    const std::size_t homeDerpIndex = ensureDerpIndex(derpRegion, derpHost, true);
    for (const PeerRuntime& peer : peers)
    {
        if (peer.Config.DerpRegion() != 0 && !peer.Config.DerpHost().empty())
        {
            (void)ensureDerp(peer.Config.DerpRegion(), peer.Config.DerpHost(), false);
        }
    }
    bool dataPathReadinessReported = false;
    const auto reportDataPathReadiness = [&]()
    {
        if (!dataPathReadinessReported &&
            session.DerpConnection(derps[homeDerpIndex].Connection).Connected())
        {
            if (dataPathReady)
            {
                dataPathReady();
            }
            dataPathReadinessReported = true;
        }
    };
    reportDataPathReadiness();
    if (configureHost && acceptDns)
    {
        WriteResolver("127.0.0.1", currentDnsDomains);
    }
    auto derpForPeer = [&](const PeerRuntime& peer) -> tailgate::derp::Connection&
    {
        auto found = std::find_if(derps.begin(),
                                  derps.end(),
                                  [&](const DerpRuntime& derp)
                                  {
                                      return derp.Region == peer.Config.DerpRegion();
                                  });
        if (found != derps.end())
        {
            return session.DerpConnection(found->Connection);
        }
        return session.DerpConnection(derps.front().Connection);
    };
    auto sendRelay = [&](const PeerRuntime& peer,
                         const std::vector<std::uint8_t>& packet,
                         tailgate::derp::DerpSendQueue::Priority priority =
                             tailgate::derp::DerpSendQueue::Priority::Data)
    {
        derpForPeer(peer).Send(peer.PublicKey, packet, priority);
    };
    auto derpForRoute = [&](const tailgate::hosted::DerpRoute& route) -> tailgate::derp::Connection*
    {
        const std::optional<tailgate::wgengine::DerpConnectionId> connection =
            hostedDerpRoutes.Resolve(route);
        return connection ? &session.DerpConnection(*connection) : nullptr;
    };

    std::vector<TailPeer> routablePeers;
    tailgate::types::netmap::NetworkConfig routableNetworkMap;
    auto rebuildRoutablePeers = [&]()
    {
        routablePeers.clear();
        routablePeers.reserve(peers.size());
        for (const PeerRuntime& peer : peers)
        {
            routablePeers.push_back(peer.Config);
        }
        routableNetworkMap.Peers(routablePeers);
    };
    rebuildRoutablePeers();

    PeerRuntime* exitPeer = nullptr;
    std::optional<std::size_t> exitPeerIndex;
    if (!exitNode.empty())
    {
        exitPeerIndex = routableNetworkMap.FindExitNode(exitNode, true);
        if (!exitPeerIndex)
        {
            throw std::runtime_error("exit node was not found in the network map: " + exitNode);
        }
        exitPeer = &peers[*exitPeerIndex];
        tailgate::base::Log(tailgate::base::LogLevel::Info,
                            "tunnel",
                            std::format("exit node={} address={}",
                                        exitPeer->Config.Name(),
                                        exitPeer->Config.Address()));
    }
    tailgate::types::netmap::NetworkConfig routerNetworkMap;
    routerNetworkMap.SelfAddress(selfIp);
    std::vector<std::string> selfAddresses{selfIp};
    if (!selfIpv6.empty())
    {
        selfAddresses.push_back(selfIpv6);
    }
    routerNetworkMap.SelfAddresses(std::move(selfAddresses));
    routerNetworkMap.DnsResolver(currentDnsResolver);
    routerNetworkMap.Peers(peerConfigs);
    tailgate::wgengine::router::Config routerConfig =
        tailgate::wgengine::router::Config::Build(routerNetworkMap,
                                                  tailgate::wgengine::router::ConfigOptions{
                                                      .AdditionalRoutes = {},
                                                      .RouteAllTraffic = exitPeer != nullptr,
                                                  });
    if (configureHost)
    {
        for (const Ipv4Prefix& route : routerConfig.Routes())
        {
            AddRoute(interfaceName, route);
        }
    }

    auto findRoute = [&](std::uint32_t destination) -> PeerRuntime*
    {
        const auto index = routableNetworkMap.FindRoute(destination, exitPeerIndex);
        return index ? &peers[*index] : nullptr;
    };
    auto findIpv6Route = [&](const std::string& destination) -> PeerRuntime*
    {
        auto found =
            std::find_if(peers.begin(),
                         peers.end(),
                         [&](const PeerRuntime& peer)
                         {
                             return std::find(peer.Config.Addresses().begin(),
                                              peer.Config.Addresses().end(),
                                              destination) != peer.Config.Addresses().end();
                         });
        return found == peers.end() ? nullptr : &*found;
    };

    auto peerForKey = [&](const tailgate::derp::DerpClient::Key& key) -> PeerRuntime*
    {
        auto found = std::find_if(peers.begin(),
                                  peers.end(),
                                  [&](const PeerRuntime& peer)
                                  {
                                      return peer.PublicKey == key;
                                  });
        return found == peers.end() ? nullptr : &*found;
    };
    auto peerForDiscoKey = [&](const tailgate::crypto::Bytes32& key) -> PeerRuntime*
    {
        auto found = std::find_if(peers.begin(),
                                  peers.end(),
                                  [&](const PeerRuntime& peer)
                                  {
                                      return peer.HasDiscoKey && peer.DiscoPublicKey == key;
                                  });
        return found == peers.end() ? nullptr : &*found;
    };
    std::vector<tailgate::derp::DerpClient::Key> unknownDerpSources;
    auto logUnknownDerpSource = [&](const tailgate::derp::DerpClient::Key& key)
    {
        if (std::find(unknownDerpSources.begin(), unknownDerpSources.end(), key) !=
            unknownDerpSources.end())
        {
            return;
        }
        unknownDerpSources.push_back(key);
        tailgate::base::Log(tailgate::base::LogLevel::Warning,
                            "derp",
                            "dropping packet from unknown source key=" +
                                tailgate::crypto::BytesToHex(key.data(), key.size()));
    };

    auto sendPeer = [&sendRelay, &connection](PeerRuntime& peer,
                                              const std::vector<std::uint8_t>& packet,
                                              bool expectResponse = true,
                                              tailgate::derp::DerpSendQueue::Priority priority =
                                                  tailgate::derp::DerpSendQueue::Priority::Data)
    {
        peer.TxBytes += packet.size();
        if (connection.HasDirectPath(peer.PublicKey))
        {
            const auto sent = connection.Send(peer.PublicKey, packet, expectResponse);
            if (sent == tailgate::wgengine::magicsock::Connection::DirectSendResult::Dropped)
            {
                tailgate::base::Log(tailgate::base::LogLevel::Warning,
                                    "tunnel",
                                    "outgoing packet limit reached for peer=" + peer.Config.Name());
            }
        }
        else
        {
            sendRelay(peer, packet, priority);
        }
    };

    auto startPeer = [&](PeerRuntime& peer)
    {
        if (!encryptedPacketTransport)
        {
            session.StartPeer(peer.PublicKey);
        }
    };

    PeerRuntime* dnsPeer =
        findRoute(tailgate::net::Ipv4Address::Parse(currentDnsResolver).HostOrder());
    if (dnsPeer == nullptr)
    {
        throw std::runtime_error("netmap does not contain a route to the DNS resolver");
    }
    if (!encryptedPacketTransport)
    {
        startPeer(*dnsPeer);
        if (exitPeer != nullptr && exitPeer != dnsPeer)
        {
            startPeer(*exitPeer);
        }
    }
    tailgate::base::Log(tailgate::base::LogLevel::Info,
                        "tunnel",
                        std::format("ready interface={} address={} dns={} peers={}",
                                    interfaceName,
                                    selfIp,
                                    currentDnsResolver,
                                    peers.size()));

    status.BackendState = "Running";
    status.Online = true;
    status.Address = selfIp;
    status.Error.clear();
    status.Peers.clear();
    for (const TailPeer& peer : peerConfigs)
    {
        if (peer.Name().empty())
        {
            continue;
        }
        tailgate::linux_frontend::PeerStatus peerStatus;
        peerStatus.Address = peer.Address();
        peerStatus.Hostname = peer.DisplayName();
        peerStatus.OperatingSystem = peer.OperatingSystem();
        peerStatus.Relay =
            peer.DerpCode().empty() ? std::format("derp-{}", peer.DerpRegion()) : peer.DerpCode();
        peerStatus.Online = peer.Online();
        peerStatus.ExitNodeOption = peer.ExitNodeOption();
        status.Peers.push_back(std::move(peerStatus));
    }
    if (persistStatus)
    {
        tailgate::linux_frontend::WriteDaemonStatus(status);
    }
    if (readyFd >= 0)
    {
        const char ready = '1';
        if (write(readyFd, &ready, 1) != 1)
        {
            tailgate::base::Log(tailgate::base::LogLevel::Warning,
                                "daemon",
                                "failed to notify parent that the tunnel is ready");
        }
        close(readyFd);
        readyFd = -1;
    }
    tailgate::linux_frontend::StatusWriter statusWriter;
    const auto submitStatus = [&](const tailgate::linux_frontend::DaemonStatus& value)
    {
        if (persistStatus)
        {
            statusWriter.Submit(value);
        }
    };

    struct PendingDns
    {
        sockaddr_in Client{};
        std::uint32_t Resolver = 0;
        std::uint16_t Id = 0;
        std::uint16_t SourcePort = 0;
        std::chrono::steady_clock::time_point Started{};
    };

    std::vector<PendingDns> pendingDnsClients;
    auto writePacket = [&](std::vector<std::uint8_t> packet)
    {
        const tailgate::wgengine::PacketWriteResult result = engine.WritePacket(std::move(packet));
        if (result == tailgate::wgengine::PacketWriteResult::Dropped ||
            result == tailgate::wgengine::PacketWriteResult::Unavailable)
        {
            throw std::runtime_error("packet device rejected an outbound packet");
        }
    };
    const auto forwardEncryptedPacket = [&](const PeerRuntime& peer,
                                            const std::vector<std::uint8_t>& packet,
                                            bool isDisco,
                                            const std::optional<sockaddr_in>& source,
                                            std::optional<tailgate::hosted::DerpRoute> derpRoute)
    {
        const tailgate::hosted::PeerPacket forwarded(peer.PublicKey,
                                                     packet,
                                                     false,
                                                     isDisco,
                                                     source ? ntohl(source->sin_addr.s_addr) : 0,
                                                     source ? ntohs(source->sin_port) : 0,
                                                     std::move(derpRoute));
        writePacket(tailgate::hosted::ProtocolCodec::EncodePeerPacket(forwarded));
    };
    UniqueFd upstreamDns = OpenUdpSocket(underlayInterface);
    UniqueFd pingServer;
    if (configureHost)
    {
        pingServer = tailgate::linux_frontend::OpenPingServer();
    }

    struct PendingPing
    {
        tailgate::disco::Disco::TransactionId Transaction{};
        tailgate::net::packet::TsmpToken TsmpToken{};
        PeerRuntime* Peer = nullptr;
        sockaddr_un Client{};
        socklen_t ClientLength = 0;
        std::chrono::steady_clock::time_point Started{};
        std::chrono::steady_clock::time_point LastSent{};
        int TimeoutSeconds = 0;
        bool Tsmp = false;
    };

    std::vector<PendingPing> pendingPings;
    auto nextPeriodicStatus = std::chrono::steady_clock::now() + StatusRefreshInterval;

    auto queueOrSend = [&](PeerRuntime& peer, std::vector<std::uint8_t> plaintext)
    {
        if (!encryptedPacketTransport)
        {
            session.SendPacketTo(peer.PublicKey, plaintext);
        }
    };
    auto handleNodeControlPacket = [&](PeerRuntime& peer, const std::vector<std::uint8_t>& packet)
    {
        if (configureHost)
        {
            if (const auto tsmpPong =
                    tailgate::net::packet::TsmpPacket::BuildPong(packet, FunnelPeerApiPort))
            {
                tailgate::base::Log(tailgate::base::LogLevel::Info,
                                    "peerapi",
                                    std::format("TSMP probe from peer={} address={}",
                                                peer.Config.Name(),
                                                peer.Config.Address()));
                queueOrSend(peer, *tsmpPong);
                return true;
            }
        }
        return false;
    };
    auto handlePacketInput = [&](std::vector<std::vector<std::uint8_t>> packets)
    {
        for (std::vector<std::uint8_t>& packet : packets)
        {
            if (encryptedPacketTransport)
            {
                const tailgate::hosted::PeerPacket transportPacket =
                    tailgate::hosted::ProtocolCodec::DecodePeerPacket(packet);
                PeerRuntime* peer = peerForKey(transportPacket.Peer());
                if (peer == nullptr)
                {
                    tailgate::base::Log(tailgate::base::LogLevel::Warning,
                                        "relay",
                                        "dropping encrypted packet for unknown peer");
                    continue;
                }
                if (transportPacket.Disco())
                {
                    tailgate::base::Log(
                        tailgate::base::LogLevel::Trace,
                        "relay",
                        std::format("forwarding hosted disco packet peer={} endpoint={}:{}",
                                    peer->Config.Name(),
                                    tailgate::net::Ipv4Address::FromHostOrder(
                                        transportPacket.EndpointAddress())
                                        .ToString(),
                                    transportPacket.EndpointPort()));
                    if (transportPacket.EndpointAddress() != 0 &&
                        transportPacket.EndpointPort() != 0)
                    {
                        sockaddr_in endpoint{};
                        endpoint.sin_family = AF_INET;
                        endpoint.sin_addr.s_addr = htonl(transportPacket.EndpointAddress());
                        endpoint.sin_port = htons(transportPacket.EndpointPort());
                        const tailgate::net::Endpoint destination = ToEndpoint(endpoint);
                        (void)connection.MarkDirect(peer->PublicKey, destination);
                        (void)connection.SendDirect(
                            peer->PublicKey, destination, transportPacket.Payload());
                    }
                    else if (transportPacket.DerpIngressRoute())
                    {
                        tailgate::derp::Connection* route =
                            derpForRoute(*transportPacket.DerpIngressRoute());
                        if (route == nullptr)
                        {
                            tailgate::base::Log(
                                tailgate::base::LogLevel::Warning,
                                "relay",
                                std::format(
                                    "dropping hosted disco packet with stale DERP route token={} "
                                    "region={}",
                                    transportPacket.DerpIngressRoute()->Token(),
                                    transportPacket.DerpIngressRoute()->Region()));
                            continue;
                        }
                        route->Send(peer->PublicKey,
                                    transportPacket.Payload(),
                                    tailgate::derp::DerpSendQueue::Priority::Control);
                    }
                    else
                    {
                        sendRelay(*peer,
                                  transportPacket.Payload(),
                                  tailgate::derp::DerpSendQueue::Priority::Control);
                        for (const std::string& endpoint : peer->Config.Endpoints())
                        {
                            if (const auto candidate = TryParseIpv4Endpoint(endpoint))
                            {
                                (void)connection.TrySendProbe(ToEndpoint(*candidate),
                                                              transportPacket.Payload());
                            }
                        }
                    }
                    continue;
                }
                sendPeer(*peer,
                         transportPacket.Payload(),
                         true,
                         transportPacket.Control()
                             ? tailgate::derp::DerpSendQueue::Priority::Control
                             : tailgate::derp::DerpSendQueue::Priority::Data);
                continue;
            }
            const std::optional<std::uint32_t> destination =
                tailgate::net::packet::Ipv4Packet::Destination(packet);
            if (destination)
            {
                if (!encryptedPacketTransport)
                {
                    session.SendPacket(packet);
                }
                continue;
            }
            const std::optional<std::string> ipv6Destination = Ipv6DestinationText(packet);
            if (!ipv6Destination)
            {
                continue;
            }
            PeerRuntime* peer = findIpv6Route(*ipv6Destination);
            if (!peer)
            {
                tailgate::base::Log(tailgate::base::LogLevel::Warning,
                                    "tunnel",
                                    std::format("dropping unroutable IPv6 packet {} -> {} ports={}",
                                                Ipv6SourceText(packet).value_or("<unknown>"),
                                                *ipv6Destination,
                                                TcpPortSummary(packet).value_or("<not-tcp>")));
                continue;
            }
            queueOrSend(*peer, std::move(packet));
        }
    };
    auto handleDnsResponse = [&](const std::vector<std::uint8_t>& packet)
    {
        for (auto pending = pendingDnsClients.begin(); pending != pendingDnsClients.end();
             ++pending)
        {
            auto payload = tailgate::net::packet::Ipv4UdpDatagram::ExtractPayload(
                packet,
                pending->Resolver,
                tailgate::net::Ipv4Address::Parse(selfIp).HostOrder(),
                53,
                pending->SourcePort);
            if (payload && payload->size() >= 2 &&
                (((static_cast<std::uint16_t>((*payload)[0]) << 8) | (*payload)[1]) == pending->Id))
            {
                SendUdp(localDns.Fd, pending->Client, *payload);
                pendingDnsClients.erase(pending);
                return true;
            }
        }
        return false;
    };

    auto completePing = [&](PendingPing& pending,
                            bool responded,
                            const std::string& endpoint,
                            std::uint16_t peerApiPort)
    {
        tailgate::linux_frontend::PingResponse response{};
        response.Responded = responded;
        response.LatencyMilliseconds =
            static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - pending.Started)
                                 .count());
        response.NodeName = pending.Peer->Config.Name();
        response.NodeAddress = pending.Peer->Config.Address();
        const std::optional<std::string> hostedPath =
            hostedConnections.PathForNode(pending.Peer->Config.NodeId());
        response.Endpoint = hostedPath.value_or(endpoint);
        response.Relay = pending.Peer->Config.DerpCode().empty()
                             ? std::format("derp-{}", pending.Peer->Config.DerpRegion())
                             : pending.Peer->Config.DerpCode();
        response.PeerApiPort = peerApiPort;
        tailgate::linux_frontend::SendPingResponse(
            pingServer.Fd, pending.Client, pending.ClientLength, response);
        pending.Peer = nullptr;
    };
    auto handlePingResponse = [&](const std::vector<std::uint8_t>& packet)
    {
        const std::optional<tailgate::net::packet::TsmpPong> pong =
            tailgate::net::packet::TsmpPacket::ParsePong(packet);
        if (!pong)
        {
            return false;
        }
        const auto pending = std::find_if(pendingPings.begin(),
                                          pendingPings.end(),
                                          [&](const PendingPing& candidate)
                                          {
                                              return candidate.Peer != nullptr && candidate.Tsmp &&
                                                     candidate.TsmpToken == pong->Token();
                                          });
        if (pending == pendingPings.end())
        {
            return true;
        }
        completePing(*pending, true, {}, pong->PeerApiPort());
        return true;
    };
    auto sendPendingPing = [&](PendingPing& pending)
    {
        if (pending.Peer == nullptr)
        {
            return;
        }
        if (pending.Tsmp)
        {
            queueOrSend(
                *pending.Peer,
                tailgate::net::packet::TsmpPacket::BuildPing(
                    tailgate::net::Ipv4Address::Parse(selfIp).HostOrder(),
                    tailgate::net::Ipv4Address::Parse(pending.Peer->Config.Address()).HostOrder(),
                    pending.TsmpToken));
            pending.LastSent = std::chrono::steady_clock::now();
            return;
        }
        const std::optional<tailgate::disco::Disco::TransactionId> transaction =
            session.SendDiscoPing(pending.Peer->PublicKey);
        if (transaction)
        {
            pending.Transaction = *transaction;
        }
        pending.LastSent = std::chrono::steady_clock::now();
    };
    auto relayName = [](const TailPeer& peer)
    {
        return peer.DerpCode().empty() ? std::format("derp-{}", peer.DerpRegion())
                                       : peer.DerpCode();
    };
    auto updateRuntimeDiscoKey = [](PeerRuntime& peer)
    {
        peer.HasDiscoKey = false;
        peer.DiscoPublicKey = {};
        if (peer.Config.DiscoKey().rfind("discokey:", 0) != 0)
        {
            return;
        }
        const auto discoKey = tailgate::crypto::HexToBytes(peer.Config.DiscoKey().substr(9));
        if (discoKey.size() == peer.DiscoPublicKey.size())
        {
            std::copy(discoKey.begin(), discoKey.end(), peer.DiscoPublicKey.begin());
            peer.HasDiscoKey = true;
        }
    };
    auto markDirect =
        [&](PeerRuntime& peer, const sockaddr_in& source, const std::string& component)
    {
        const std::string endpoint =
            std::format("{}:{}", inet_ntoa(source.sin_addr), ntohs(source.sin_port));
        bool changed = false;
        for (auto& peerStatus : status.Peers)
        {
            if (peerStatus.Address == peer.Config.Address())
            {
                const bool statusChanged = !peerStatus.Direct || !peerStatus.Active ||
                                           !peerStatus.Online || peerStatus.Endpoint != endpoint;
                peerStatus.Direct = true;
                peerStatus.Active = true;
                peerStatus.Online = true;
                peerStatus.Endpoint = endpoint;
                if (statusChanged)
                {
                    changed = true;
                    submitStatus(status);
                }
            }
        }
        if (changed)
        {
            tailgate::base::Log(
                tailgate::base::LogLevel::Info,
                component,
                std::format("direct peer={} endpoint={}", peer.Config.Name(), endpoint));
        }
    };
    auto handleWireGuardEvent = [&](tailgate::wgengine::SessionWireGuardEvent event)
    {
        PeerRuntime* peer = peerForKey(event.Peer);
        if (peer == nullptr)
        {
            return;
        }
        for (std::vector<std::uint8_t>& plain : event.Plaintext)
        {
            if (handleNodeControlPacket(*peer, plain) || handlePingResponse(plain) ||
                handleDnsResponse(plain))
            {
                continue;
            }
            writePacket(std::move(plain));
        }
    };
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
    EventHandle pingEvent;
    if (pingServer.Fd >= 0)
    {
        pingEvent = eventRegistry.Register(pingServer.Fd,
                                           EventInterest::Readable,
                                           DataplaneEvent(DataplaneEvent::Kind::Ping).Token());
    }
    EventHandle relayControlEvent;
    if (relayControlFd >= 0)
    {
        relayControlEvent =
            eventRegistry.Register(relayControlFd,
                                   EventInterest::Readable,
                                   DataplaneEvent(DataplaneEvent::Kind::RelayControl).Token());
    }
    auto applyStatusFromNetworkMap = [&](const tailgate::types::netmap::NetworkConfig& config)
    {
        bool changed = false;
        for (const TailPeer& peer : config.Peers())
        {
            if (peer.Name().empty())
            {
                continue;
            }
            auto existing = std::find_if(status.Peers.begin(),
                                         status.Peers.end(),
                                         [&](const tailgate::linux_frontend::PeerStatus& peerStatus)
                                         {
                                             return peerStatus.Address == peer.Address();
                                         });
            if (existing == status.Peers.end())
            {
                tailgate::linux_frontend::PeerStatus added;
                added.Address = peer.Address();
                added.Hostname = peer.DisplayName();
                added.OperatingSystem = peer.OperatingSystem();
                added.Relay = relayName(peer);
                added.Online = peer.Online();
                added.ExitNodeOption = peer.ExitNodeOption();
                status.Peers.push_back(std::move(added));
                changed = true;
                continue;
            }

            const bool shouldClearActivity = !peer.Online();
            changed = changed || existing->Hostname != peer.DisplayName() ||
                      existing->OperatingSystem != peer.OperatingSystem() ||
                      existing->Relay != relayName(peer) || existing->Online != peer.Online() ||
                      existing->ExitNodeOption != peer.ExitNodeOption() ||
                      (shouldClearActivity &&
                       (existing->Active || existing->Direct || !existing->Endpoint.empty() ||
                        existing->TxBytes != 0 || existing->RxBytes != 0));
            existing->Hostname = peer.DisplayName();
            existing->OperatingSystem = peer.OperatingSystem();
            existing->Relay = relayName(peer);
            existing->Online = peer.Online();
            existing->ExitNodeOption = peer.ExitNodeOption();
            if (shouldClearActivity)
            {
                existing->Active = false;
                existing->Direct = false;
                existing->Endpoint.clear();
                existing->TxBytes = 0;
                existing->RxBytes = 0;
            }
        }

        const auto known = [&config](const tailgate::linux_frontend::PeerStatus& peerStatus)
        {
            return std::any_of(config.Peers().begin(),
                               config.Peers().end(),
                               [&](const TailPeer& peer)
                               {
                                   return peer.Address() == peerStatus.Address;
                               });
        };
        const std::size_t oldSize = status.Peers.size();
        status.Peers.erase(std::remove_if(status.Peers.begin(),
                                          status.Peers.end(),
                                          [&](const tailgate::linux_frontend::PeerStatus& peer)
                                          {
                                              return !known(peer);
                                          }),
                           status.Peers.end());
        changed = changed || status.Peers.size() != oldSize;
        if (changed)
        {
            submitStatus(status);
        }
    };

    auto applyNetworkMap = [&](const tailgate::types::netmap::NetworkConfig& config)
    {
        TimedSection("control DERP apply",
                     [&]()
                     {
                         (void)ensureDerpIndex(config.DerpRegion(), config.DerpHost(), false);
                         for (const TailPeer& peer : config.Peers())
                         {
                             if (peer.DerpRegion() != 0 && !peer.DerpHost().empty())
                             {
                                 (void)ensureDerpIndex(peer.DerpRegion(), peer.DerpHost(), false);
                             }
                         }
                     });

        TimedSection(
            "control peer apply",
            [&]()
            {
                for (const TailPeer& configPeer : config.Peers())
                {
                    auto existing =
                        std::find_if(peers.begin(),
                                     peers.end(),
                                     [&](const PeerRuntime& peer)
                                     {
                                         return (configPeer.NodeId() != 0 &&
                                                 peer.Config.NodeId() == configPeer.NodeId()) ||
                                                peer.Config.Address() == configPeer.Address();
                                     });
                    if (existing == peers.end())
                    {
                        std::optional<PeerRuntime> runtime = buildPeerRuntime(configPeer);
                        if (!runtime)
                        {
                            continue;
                        }
                        peers.push_back(std::move(*runtime));
                        tailgate::base::Log(
                            tailgate::base::LogLevel::Info,
                            "control",
                            std::format(
                                "added peer from network-map update: {} version={} ingress={} "
                                "wire-ingress={} peerapi4={} peerapi6={}",
                                configPeer.Name(),
                                configPeer.ClientVersion(),
                                configPeer.IngressEnabled() ? 1 : 0,
                                configPeer.WireIngress() ? 1 : 0,
                                configPeer.PeerApi4Port(),
                                configPeer.PeerApi6Port()));
                        continue;
                    }

                    if (existing->Config.Key() != configPeer.Key())
                    {
                        tailgate::base::Log(
                            tailgate::base::LogLevel::Info,
                            "control",
                            std::format("peer key generation changed name={} address={} "
                                        "old-node={} new-node={}",
                                        configPeer.Name(),
                                        configPeer.Address(),
                                        existing->Config.NodeId(),
                                        configPeer.NodeId()));
                        const std::vector<std::uint8_t> publicKeyBytes =
                            tailgate::crypto::HexToBytes(configPeer.Key().substr(8));
                        if (publicKeyBytes.size() == existing->PublicKey.size())
                        {
                            tailgate::crypto::Bytes32 nextPublicKey{};
                            std::copy(publicKeyBytes.begin(),
                                      publicKeyBytes.end(),
                                      nextPublicKey.begin());
                            if (encryptedPacketTransport && !connection.AddPeer(nextPublicKey))
                            {
                                continue;
                            }
                            if (encryptedPacketTransport)
                            {
                                (void)connection.RemovePeer(existing->PublicKey);
                            }
                            existing->PublicKey = nextPublicKey;
                            if (encryptedPacketTransport)
                            {
                                connection.ResetPath(existing->PublicKey,
                                                     tailgate::wgengine::magicsock::PeerPathState::
                                                         ResetMode::ForgetVerifiedEndpoints);
                            }
                        }
                    }
                    const bool endpointsChanged =
                        existing->Config.Endpoints() != configPeer.Endpoints();
                    const bool discoKeyChanged =
                        existing->Config.DiscoKey() != configPeer.DiscoKey();
                    const bool onlineChanged = existing->Config.Online() != configPeer.Online();
                    existing->Config = configPeer;
                    updateRuntimeDiscoKey(*existing);
                    if (onlineChanged || discoKeyChanged || endpointsChanged)
                    {
                        tailgate::base::Log(
                            tailgate::base::LogLevel::Info,
                            "control",
                            std::format("peer update name={} online={} disco={} endpoints={} "
                                        "version={} ingress={} wire-ingress={} peerapi4={} "
                                        "peerapi6={}",
                                        configPeer.Name(),
                                        configPeer.Online() ? 1 : 0,
                                        existing->HasDiscoKey ? 1 : 0,
                                        configPeer.Endpoints().size(),
                                        configPeer.ClientVersion(),
                                        configPeer.IngressEnabled() ? 1 : 0,
                                        configPeer.WireIngress() ? 1 : 0,
                                        configPeer.PeerApi4Port(),
                                        configPeer.PeerApi6Port()));
                    }
                    if (encryptedPacketTransport && (!configPeer.Online() || endpointsChanged))
                    {
                        connection.ResetPath(existing->PublicKey,
                                             !configPeer.Online() || discoKeyChanged
                                                 ? tailgate::wgengine::magicsock::PeerPathState::
                                                       ResetMode::ForgetVerifiedEndpoints
                                                 : tailgate::wgengine::magicsock::PeerPathState::
                                                       ResetMode::PreserveVerifiedEndpoints);
                    }
                }
                if (!encryptedPacketTransport)
                {
                    session.UpdatePeers(config.Peers(), exitNode);
                }
            });

        TimedSection(
            "control route apply",
            [&]()
            {
                TimedSection(
                    "control peer pruning",
                    [&]()
                    {
                        for (PeerRuntime& peer : peers)
                        {
                            const bool stillPresent = std::any_of(
                                config.Peers().begin(),
                                config.Peers().end(),
                                [&](const TailPeer& configPeer)
                                {
                                    return (configPeer.NodeId() != 0 &&
                                            peer.Config.NodeId() == configPeer.NodeId()) ||
                                           peer.Config.Address() == configPeer.Address();
                                });
                            if (!stillPresent)
                            {
                                if (!peer.Config.AllowedPrefixes().empty())
                                {
                                    tailgate::base::Log(
                                        tailgate::base::LogLevel::Info,
                                        "control",
                                        std::format("peer generation removed name={} address={} "
                                                    "node={}",
                                                    peer.Config.Name(),
                                                    peer.Config.Address(),
                                                    peer.Config.NodeId()));
                                }
                                peer.Config.Online(false);
                                peer.Config.AllowedPrefixes({});
                                peer.Config.ExitNodeOption(false);
                                if (encryptedPacketTransport)
                                {
                                    connection.ResetPath(
                                        peer.PublicKey,
                                        tailgate::wgengine::magicsock::PeerPathState::ResetMode::
                                            ForgetVerifiedEndpoints);
                                }
                            }
                        }
                    });

                TimedSection(
                    "control DNS config apply",
                    [&]()
                    {
                        const bool resolverChanged = currentDnsResolver != config.DnsResolver();
                        const bool domainsChanged = currentDnsDomains != config.DnsDomains();
                        if (resolverChanged)
                        {
                            currentDnsResolver = config.DnsResolver();
                        }
                        currentDnsDomains = config.DnsDomains();
                        currentDnsDefaultResolvers = config.DnsDefaultResolvers();
                        currentDnsRoutes = config.DnsRoutes();
                        if (configureHost && acceptDns && (resolverChanged || domainsChanged))
                        {
                            WriteResolver("127.0.0.1", currentDnsDomains);
                        }
                    });

                TimedSection(
                    "control route rebuild",
                    [&]()
                    {
                        rebuildRoutablePeers();
                        if (!exitNode.empty())
                        {
                            exitPeerIndex = routableNetworkMap.FindExitNode(exitNode, true);
                            exitPeer = exitPeerIndex ? &peers[*exitPeerIndex] : nullptr;
                        }
                        const tailgate::wgengine::router::Config nextRouterConfig =
                            tailgate::wgengine::router::Config::Build(
                                config,
                                tailgate::wgengine::router::ConfigOptions{
                                    .AdditionalRoutes = {},
                                    .RouteAllTraffic = exitPeer != nullptr,
                                });
                        if (configureHost)
                        {
                            ApplyRouteChanges(interfaceName, routerConfig, nextRouterConfig);
                        }
                        routerConfig = nextRouterConfig;
                        dnsPeer = findRoute(
                            tailgate::net::Ipv4Address::Parse(currentDnsResolver).HostOrder());
                    });
                TimedSection("control handshake refresh",
                             [&]()
                             {
                                 if (encryptedPacketTransport)
                                 {
                                     return;
                                 }
                                 if (dnsPeer != nullptr)
                                 {
                                     startPeer(*dnsPeer);
                                 }
                                 if (exitPeer != nullptr && exitPeer != dnsPeer)
                                 {
                                     startPeer(*exitPeer);
                                 }
                             });
                TimedSection("control status apply",
                             [&]()
                             {
                                 applyStatusFromNetworkMap(config);
                             });
            });
        tailgate::base::Log(
            tailgate::base::LogLevel::Info,
            "control",
            std::format("applied live network-map update: peers={}", config.Peers().size()));
        if (networkMapUpdated)
        {
            networkMapUpdated(config);
        }
    };

    while (!Lifecycle::Stopping() && !Lifecycle::Reloading())
    {
        const std::size_t maximumEvents =
            std::max<std::size_t>(16, peers.size() + session.DerpConnectionCount() + 7);
        tailgate::wgengine::SessionWaitResult waitResult =
            session.Wait(maximumEvents, MaximumPacketsPerDescriptorCycle, RelayPacketBufferSize);
        reportDataPathReadiness();
        if (waitResult.Status == tailgate::base::EventWaitStatus::Woken)
        {
            continue;
        }

        bool localDnsInput = false;
        bool upstreamDnsInput = false;
        bool pingInput = false;
        bool relayControlInput = false;
        const bool maintenanceExpired = waitResult.MaintenanceDue;
        if (!waitResult.Failures.empty())
        {
            throw std::system_error(std::make_error_code(std::errc::network_down));
        }
        for (const tailgate::base::Event& event : waitResult.PlatformEvents)
        {
            const DataplaneEvent dataplaneEvent = DataplaneEvent::FromValue(event.Token.Value);
            switch (dataplaneEvent.Type())
            {
            case DataplaneEvent::Kind::Tun:
                break;
            case DataplaneEvent::Kind::LocalDns:
                localDnsInput =
                    localDnsInput || HasReadiness(event.Readiness, EventReadiness::Readable);
                break;
            case DataplaneEvent::Kind::Derp:
                break;
            case DataplaneEvent::Kind::UpstreamDns:
                upstreamDnsInput =
                    upstreamDnsInput || HasReadiness(event.Readiness, EventReadiness::Readable);
                break;
            case DataplaneEvent::Kind::Ping:
                pingInput = pingInput || HasReadiness(event.Readiness, EventReadiness::Readable);
                break;
            case DataplaneEvent::Kind::AdvertisedUdp:
                break;
            case DataplaneEvent::Kind::Control:
                break;
            case DataplaneEvent::Kind::RelayControl:
                relayControlInput =
                    relayControlInput || HasReadiness(event.Readiness, EventReadiness::Readable);
                break;
            }
        }

        for (const tailgate::types::netmap::NetworkConfig& update : waitResult.NetworkMaps)
        {
            applyNetworkMap(update);
        }
        for (tailgate::wgengine::SessionWireGuardEvent& event : waitResult.WireGuardEvents)
        {
            handleWireGuardEvent(std::move(event));
        }
        for (const tailgate::wgengine::SessionPathEvent& event : waitResult.PathEvents)
        {
            PeerRuntime* peer = peerForKey(event.Peer);
            if (peer == nullptr)
            {
                continue;
            }
            if (event.DirectEndpoint)
            {
                markDirect(*peer, ToSockaddr(*event.DirectEndpoint), "magicsock");
            }
            else
            {
                for (auto& peerStatus : status.Peers)
                {
                    if (peerStatus.Address == peer->Config.Address())
                    {
                        peerStatus.Direct = false;
                        peerStatus.Endpoint.clear();
                    }
                }
                submitStatus(status);
            }
        }
        for (const tailgate::wgengine::SessionDiscoEvent& event : waitResult.DiscoEvents)
        {
            if (event.Type != tailgate::disco::Disco::MessageType::Pong)
            {
                continue;
            }
            const auto pending = std::find_if(pendingPings.begin(),
                                              pendingPings.end(),
                                              [&](const PendingPing& candidate)
                                              {
                                                  return candidate.Peer != nullptr &&
                                                         !candidate.Tsmp &&
                                                         candidate.Peer->PublicKey == event.Peer &&
                                                         candidate.Transaction == event.Transaction;
                                              });
            if (pending != pendingPings.end())
            {
                completePing(*pending,
                             true,
                             event.DirectSource ? event.DirectSource->ToString() : std::string{},
                             0);
            }
        }
        if (relayControlInput && relayControlFd >= 0)
        {
            std::vector<std::uint8_t> payload(tailgate::hosted::Frame::MaximumEncodedSize);
            const ssize_t received = recv(relayControlFd, payload.data(), payload.size(), 0);
            if (received <= 0)
            {
                throw std::runtime_error("relay control channel closed");
            }
            payload.resize(static_cast<std::size_t>(received));
            tailgate::hosted::Decoder decoder;
            decoder.Feed(payload);
            const std::optional<tailgate::hosted::Frame> frame = decoder.Next();
            if (!frame || decoder.Next())
            {
                throw std::runtime_error("relay control channel returned an invalid frame");
            }
            if (frame->Type() == tailgate::hosted::MessageType::NetworkMap)
            {
                applyNetworkMap(
                    tailgate::hosted::ProtocolCodec::DecodeNetworkConfig(frame->Payload()));
            }
            else if (frame->Type() == tailgate::hosted::MessageType::PeerEndpoint)
            {
                if (!encryptedPacketTransport)
                {
                    throw std::runtime_error("relay endpoint update requires encrypted transport");
                }
                const tailgate::hosted::PeerEndpoint endpoint =
                    tailgate::hosted::ProtocolCodec::DecodePeerEndpoint(frame->Payload());
                PeerRuntime* peer = peerForKey(endpoint.Peer());
                if (peer != nullptr && connection.MarkDirect(peer->PublicKey, endpoint.Endpoint()))
                {
                    tailgate::base::Log(
                        tailgate::base::LogLevel::Info,
                        "relay",
                        std::format("verified hosted peer endpoint peer={} endpoint={}",
                                    peer->Config.Name(),
                                    endpoint.Endpoint().ToString()));
                }
            }
            else
            {
                throw std::runtime_error("relay control channel returned an unexpected frame");
            }
        }

        if (localDnsInput)
        {
            TimedSection(
                "local DNS",
                [&]()
                {
                    sockaddr_in client{};
                    std::vector<std::uint8_t> dnsPayload = ReceiveUdp(localDns.Fd, &client);
                    if (dnsPayload.size() >= 2)
                    {
                        std::uint16_t dnsId =
                            (static_cast<std::uint16_t>(dnsPayload[0]) << 8) | dnsPayload[1];
                        const std::vector<std::string>& defaultResolvers =
                            currentDnsDefaultResolvers.empty() ? originalResolvers
                                                               : currentDnsDefaultResolvers;
                        const std::optional<tailgate::net::dns::ResolverSelection> selection =
                            tailgate::net::dns::SelectResolver(
                                dnsPayload, currentDnsResolver, currentDnsRoutes, defaultResolvers);
                        if (!selection || !tailgate::net::Ipv4Address::TryParse(selection->Address))
                        {
                            throw std::runtime_error("DNS resolver transport is unsupported");
                        }
                        const std::string& selectedResolver = selection->Address;
                        const std::uint32_t resolverAddress =
                            tailgate::net::Ipv4Address::Parse(selectedResolver).HostOrder();
                        const std::uint16_t sourcePort = ntohs(client.sin_port);
                        pendingDnsClients.erase(
                            std::remove_if(pendingDnsClients.begin(),
                                           pendingDnsClients.end(),
                                           [&](const PendingDns& pending)
                                           {
                                               return pending.Id == dnsId &&
                                                      pending.SourcePort == sourcePort &&
                                                      pending.Client.sin_addr.s_addr ==
                                                          client.sin_addr.s_addr &&
                                                      pending.Client.sin_port == client.sin_port;
                                           }),
                            pendingDnsClients.end());
                        pendingDnsClients.push_back(
                            PendingDns{.Client = client,
                                       .Resolver = resolverAddress,
                                       .Id = dnsId,
                                       .SourcePort = sourcePort,
                                       .Started = std::chrono::steady_clock::now()});
                        PeerRuntime* peer = findRoute(resolverAddress);
                        if (peer)
                        {
                            std::vector<std::uint8_t> dnsPacket =
                                tailgate::net::packet::Ipv4UdpDatagram::Build(
                                    tailgate::net::Ipv4Address::Parse(selfIp).HostOrder(),
                                    resolverAddress,
                                    sourcePort,
                                    53,
                                    dnsPayload);
                            queueOrSend(*peer, std::move(dnsPacket));
                        }
                        else
                        {
                            sockaddr_in endpoint{};
                            endpoint.sin_family = AF_INET;
                            endpoint.sin_addr.s_addr = htonl(resolverAddress);
                            endpoint.sin_port = htons(53);
                            SendUdp(upstreamDns.Fd, endpoint, dnsPayload);
                        }
                    }
                });
        }

        if (upstreamDnsInput)
        {
            TimedSection("upstream DNS",
                         [&]()
                         {
                             sockaddr_in source{};
                             const std::vector<std::uint8_t> response =
                                 ReceiveUdp(upstreamDns.Fd, &source);
                             if (response.size() >= 2)
                             {
                                 const std::uint16_t dnsId =
                                     (static_cast<std::uint16_t>(response[0]) << 8) | response[1];
                                 const auto pending = std::find_if(
                                     pendingDnsClients.begin(),
                                     pendingDnsClients.end(),
                                     [&](const PendingDns& candidate)
                                     {
                                         return candidate.Id == dnsId &&
                                                candidate.Resolver == ntohl(source.sin_addr.s_addr);
                                     });
                                 if (pending != pendingDnsClients.end() &&
                                     pending->Resolver == ntohl(source.sin_addr.s_addr))
                                 {
                                     SendUdp(localDns.Fd, pending->Client, response);
                                     pendingDnsClients.erase(pending);
                                 }
                             }
                         });
        }

        if (pingInput)
        {
            TimedSection("ping IPC",
                         [&]()
                         {
                             tailgate::linux_frontend::PingRequest request{};
                             sockaddr_un client{};
                             socklen_t clientLength = sizeof(client);
                             if (tailgate::linux_frontend::ReceivePingRequest(
                                     pingServer.Fd, request, client, clientLength))
                             {
                                 const auto found = std::find_if(
                                     peers.begin(),
                                     peers.end(),
                                     [&](const PeerRuntime& peer)
                                     {
                                         return peer.Config.MatchesTarget(request.Target);
                                     });
                                 const bool tsmp = request.Tsmp;
                                 const bool canDisco = found != peers.end() &&
                                                       (encryptedPacketTransport
                                                            ? found->HasDiscoKey
                                                            : session.CanDisco(found->PublicKey));
                                 if (found == peers.end() || (!tsmp && !canDisco))
                                 {
                                     tailgate::base::Log(
                                         tailgate::base::LogLevel::Warning,
                                         "ping",
                                         found == peers.end()
                                             ? "target not found: " + request.Target
                                             : std::format("target has no disco key: {} online={}",
                                                           found->Config.Name(),
                                                           found->Config.Online() ? 1 : 0));
                                     tailgate::linux_frontend::PingResponse response{};
                                     tailgate::linux_frontend::SendPingResponse(
                                         pingServer.Fd, client, clientLength, response);
                                 }
                                 else
                                 {
                                     PendingPing pending;
                                     pending.Tsmp = tsmp;
                                     if (tsmp)
                                     {
                                         const tailgate::crypto::Bytes32 random =
                                             tailgate::crypto::GeneratePrivateKey();
                                         std::copy_n(random.begin(),
                                                     pending.TsmpToken.size(),
                                                     pending.TsmpToken.begin());
                                     }
                                     else
                                     {
                                         pending.Transaction = {};
                                     }
                                     pending.Peer = &*found;
                                     pending.Client = client;
                                     pending.ClientLength = clientLength;
                                     pending.Started = std::chrono::steady_clock::now();
                                     pending.TimeoutSeconds = std::max(1, request.TimeoutSeconds);
                                     pendingPings.push_back(std::move(pending));
                                     sendPendingPing(pendingPings.back());
                                 }
                             }
                         });
        }

        if (!waitResult.Packets.empty())
        {
            TimedSection("packet-device input",
                         [&]()
                         {
                             handlePacketInput(std::move(waitResult.Packets));
                         });
        }

        TimedSection(
            "magicsock UDP",
            [&]()
            {
                for (const auto& receivedDatagram : waitResult.Datagrams)
                {
                    const std::vector<std::uint8_t>& data = receivedDatagram.Payload;
                    const sockaddr_in source = ToSockaddr(receivedDatagram.Source);
                    PeerRuntime* peer = nullptr;
                    if (tailgate::disco::Disco::IsDiscoPacket(data))
                    {
                        if (data.size() < 38)
                        {
                            continue;
                        }
                        tailgate::crypto::Bytes32 sender{};
                        std::copy_n(data.begin() + 6, sender.size(), sender.begin());
                        peer = peerForDiscoKey(sender);
                        if (peer != nullptr)
                        {
                            peer->RxBytes += data.size();
                            if (encryptedPacketTransport)
                            {
                                forwardEncryptedPacket(*peer, data, true, source, std::nullopt);
                            }
                        }
                        continue;
                    }
                    if (encryptedPacketTransport)
                    {
                        const std::optional<tailgate::crypto::Bytes32> sourcePeer =
                            connection.AcceptDirectSource(receivedDatagram.Source);
                        auto found = std::find_if(peers.begin(),
                                                  peers.end(),
                                                  [&](const PeerRuntime& candidate)
                                                  {
                                                      return sourcePeer &&
                                                             candidate.PublicKey == *sourcePeer;
                                                  });
                        if (found != peers.end())
                        {
                            found->RxBytes += data.size();
                            forwardEncryptedPacket(*found, data, false, source, std::nullopt);
                        }
                        continue;
                    }
                    continue;
                }
            });

        TimedSection(
            "DERP notify",
            [&]()
            {
                for (tailgate::wgengine::SessionDerpPacket& receivedPacket : waitResult.DerpPackets)
                {
                    const tailgate::derp::DerpClient::Packet& packet = receivedPacket.Packet;
                    PeerRuntime* peer = peerForKey(packet.Source);
                    if (peer == nullptr)
                    {
                        logUnknownDerpSource(packet.Source);
                        continue;
                    }
                    peer->RxBytes += packet.Payload.size();
                    if (tailgate::disco::Disco::IsDiscoPacket(packet.Payload))
                    {
                        PeerRuntime* discoPeer = nullptr;
                        if (packet.Payload.size() >= 38)
                        {
                            tailgate::crypto::Bytes32 sender{};
                            std::copy_n(packet.Payload.begin() + 6, sender.size(), sender.begin());
                            discoPeer = peerForDiscoKey(sender);
                        }
                        if (discoPeer != nullptr)
                        {
                            if (encryptedPacketTransport)
                            {
                                const auto derp = std::ranges::find_if(
                                    derps,
                                    [&](const DerpRuntime& candidate)
                                    {
                                        return candidate.Connection == receivedPacket.Connection;
                                    });
                                if (derp == derps.end())
                                {
                                    tailgate::base::Log(tailgate::base::LogLevel::Warning,
                                                        "relay",
                                                        "dropping hosted disco packet from an "
                                                        "unknown DERP connection");
                                    continue;
                                }
                                forwardEncryptedPacket(
                                    *discoPeer, packet.Payload, true, std::nullopt, derp->Route);
                            }
                        }
                        else
                        {
                            tailgate::base::Log(
                                tailgate::base::LogLevel::Debug,
                                "disco",
                                std::format(
                                    "dropping DERP disco packet from unmatched disco key={} "
                                    "source-peer={}",
                                    packet.Payload.size() >= 38
                                        ? tailgate::crypto::BytesToHex(packet.Payload.data() + 6, 8)
                                        : "<short>",
                                    peer->Config.Name()));
                        }
                        continue;
                    }
                    if (encryptedPacketTransport)
                    {
                        forwardEncryptedPacket(
                            *peer, packet.Payload, false, std::nullopt, std::nullopt);
                        continue;
                    }
                    continue;
                }
            });

        if (maintenanceExpired)
        {
            TimedSection(
                "timers",
                [&]()
                {
                    for (PeerRuntime& peer : peers)
                    {
                        if (encryptedPacketTransport && connection.ExpireDirectPath(peer.PublicKey))
                        {
                            tailgate::base::Log(tailgate::base::LogLevel::Info,
                                                "tunnel",
                                                "relay fallback peer=" + peer.Config.Name());
                            for (auto& peerStatus : status.Peers)
                            {
                                if (peerStatus.Address == peer.Config.Address())
                                {
                                    peerStatus.Direct = false;
                                    peerStatus.Endpoint.clear();
                                }
                            }
                            submitStatus(status);
                        }
                        if (encryptedPacketTransport)
                        {
                            continue;
                        }
                        const std::optional<tailgate::wgengine::SessionPeerStats> peerStats =
                            session.PeerStats(peer.PublicKey);
                        for (auto& peerStatus : status.Peers)
                        {
                            if (peerStatus.Address == peer.Config.Address() && peerStats)
                            {
                                peerStatus.Active = peerStats->WireGuardSession;
                                peerStatus.TxBytes = peerStats->TransmittedBytes;
                                peerStatus.RxBytes = peerStats->ReceivedBytes;
                            }
                        }
                    }
                });
            TimedSection(
                "bookkeeping",
                [&]()
                {
                    for (PendingPing& pending : pendingPings)
                    {
                        if (pending.Peer != nullptr &&
                            std::chrono::steady_clock::now() - pending.Started >=
                                std::chrono::seconds(pending.TimeoutSeconds))
                        {
                            tailgate::base::Log(
                                tailgate::base::LogLevel::Warning,
                                "ping",
                                std::format("timeout peer={} online={} disco={} endpoints={}",
                                            pending.Peer->Config.Name(),
                                            pending.Peer->Config.Online() ? 1 : 0,
                                            pending.Peer->HasDiscoKey ? 1 : 0,
                                            pending.Peer->Config.Endpoints().size()));
                            completePing(pending, false, {}, 0);
                        }
                        else if (pending.Peer != nullptr && !pending.Tsmp &&
                                 std::chrono::steady_clock::now() - pending.LastSent >=
                                     PingRetryInterval)
                        {
                            sendPendingPing(pending);
                        }
                    }
                    pendingPings.erase(std::remove_if(pendingPings.begin(),
                                                      pendingPings.end(),
                                                      [](const PendingPing& pending)
                                                      {
                                                          return pending.Peer == nullptr;
                                                      }),
                                       pendingPings.end());
                    const auto now = std::chrono::steady_clock::now();
                    pendingDnsClients.erase(std::remove_if(pendingDnsClients.begin(),
                                                           pendingDnsClients.end(),
                                                           [&](const PendingDns& pending)
                                                           {
                                                               return now - pending.Started >=
                                                                      PendingDnsTimeout;
                                                           }),
                                            pendingDnsClients.end());
                    if (now >= nextPeriodicStatus)
                    {
                        submitStatus(status);
                        nextPeriodicStatus = now + StatusRefreshInterval;
                    }
                });
        }
    }
    if (configureHost)
    {
        unlink(tailgate::linux_frontend::PingSocketPath().c_str());
    }
}

} // namespace tailgate::linux_frontend
