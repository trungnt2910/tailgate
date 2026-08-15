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
#include <random>
#include <stdexcept>
#include <string>
#include <syncstream>
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
#include <sys/epoll.h>
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
#include <tailgate/control/base/ControlHandshake.h>
#include <tailgate/control/client/ControlClient.h>
#include <tailgate/control/client/RetryBackoff.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/derp/Client.h>
#include <tailgate/di/Bindings.h>
#include <tailgate/disco/Disco.h>
#include <tailgate/hosted/DiscoProbes.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/net/packet/Tsmp.h>
#include <tailgate/net/stun/Stun.h>
#include <tailgate/net/tls/TlsStream.h>
#include <tailgate/qr/QrCode.h>
#include <tailgate/serve/FunnelConfig.h>
#include <tailgate/serve/acme/Client.h>
#include <tailgate/wgengine/magicsock/PeerPathState.h>
#include <tailgate/wgengine/wireguard/Router.h>
#include <tailgate/wgengine/wireguard/Tunnel.h>

#include "ControlStream.h"
#include "LinuxAcme.h"
#include "LinuxCaBundle.h"
#include "LinuxDataplaneEvents.h"
#include "LinuxDerpWorker.h"
#include "LinuxFiles.h"
#include "LinuxHost.h"
#include "LinuxNetwork.h"
#include "LinuxPeerApiServer.h"
#include "LinuxPingIpc.h"
#include "LinuxQrCode.h"
#include "LinuxRelayServer.h"
#include "LinuxState.h"
#include "LinuxStatusWriter.h"
#include "TcpStream.h"
#include "UniqueFd.h"

namespace
{

volatile std::sig_atomic_t StopRequested = 0;
volatile std::sig_atomic_t ReloadRequested = 0;
volatile std::sig_atomic_t StartupInterrupted = 0;
volatile std::sig_atomic_t StartupDaemonPid = 0;

void HandleStopSignal(int)
{
    StopRequested = 1;
}

void HandleReloadSignal(int)
{
    ReloadRequested = 1;
}

void HandleStartupSignal(int)
{
    StartupInterrupted = 1;
    if (StartupDaemonPid > 0)
    {
        kill(static_cast<pid_t>(StartupDaemonPid), SIGTERM);
    }
}

using tailgate::linux_frontend::AddEpollInterest;
using tailgate::linux_frontend::AddRoute;
using tailgate::linux_frontend::CreateDeadlineTimerFd;
using tailgate::linux_frontend::CreateTimerFd;
using tailgate::linux_frontend::DataplaneEvent;
using tailgate::linux_frontend::DataplaneEventKind;
using tailgate::linux_frontend::DefaultRouteInterface;
using tailgate::linux_frontend::DerpWorker;
using tailgate::linux_frontend::DrainTimerFd;
using tailgate::linux_frontend::InterfaceIpv4Address;
using tailgate::linux_frontend::ModifyEpollInterest;
using tailgate::linux_frontend::OpenLocalDnsSocket;
using tailgate::linux_frontend::OpenTun;
using tailgate::linux_frontend::OpenUdpSocket;
using tailgate::linux_frontend::PackDataplaneEvent;
using tailgate::linux_frontend::ParseIpv4Endpoint;
using tailgate::linux_frontend::ReadResolverAddresses;
using tailgate::linux_frontend::ReceiveUdp;
using tailgate::linux_frontend::RemoveRoute;
using tailgate::linux_frontend::ResetDeadlineTimerFd;
using tailgate::linux_frontend::SendUdp;
using tailgate::linux_frontend::SetInterfaceAddress;
using tailgate::linux_frontend::SetInterfaceIpv6Address;
using tailgate::linux_frontend::SetInterfaceMtu;
using tailgate::linux_frontend::SocketPort;
using tailgate::linux_frontend::TryParseIpv4Endpoint;
using tailgate::linux_frontend::TrySendUdp;
using tailgate::linux_frontend::UniqueFd;
using tailgate::linux_frontend::UnpackDataplaneEvent;
using tailgate::linux_frontend::WriteAll;
using tailgate::linux_frontend::WriteResolver;
using Ipv4Prefix = tailgate::net::packet::Ipv4Prefix;
using TailPeer = tailgate::types::netmap::PeerConfig;

[[nodiscard]] std::optional<std::string> HostedPathForNode(std::uint64_t nodeId);

struct PeerRuntime
{
    TailPeer Config;
    tailgate::wgengine::wireguard::WireGuardTunnel::PeerId TunnelPeer = 0;
    UniqueFd Socket;
    bool UseAdvertisedSocket = false;
    tailgate::wgengine::magicsock::PeerPathState Path;
    tailgate::disco::Disco::TransactionId DirectProbeTransaction{};
    tailgate::wgengine::wireguard::WireGuardTunnel::Key PublicKey{};
    tailgate::crypto::Bytes32 DiscoPublicKey{};
    bool HasDiscoKey = false;
    std::uint64_t TxBytes = 0;
    std::uint64_t RxBytes = 0;
    std::deque<std::vector<std::uint8_t>> PendingPackets;
    std::size_t PendingBytes = 0;
    std::deque<std::vector<std::uint8_t>> OutgoingPackets;
    std::size_t OutgoingBytes = 0;
    std::uint64_t UdpBackpressureEvents = 0;
    std::chrono::steady_clock::time_point LastBackpressureLog{};
    std::chrono::steady_clock::time_point LastHandshake{};
};

tailgate::wgengine::magicsock::Endpoint ToMagicsockEndpoint(const sockaddr_in& endpoint)
{
    return tailgate::wgengine::magicsock::Endpoint{
        .Address = ntohl(endpoint.sin_addr.s_addr),
        .Port = ntohs(endpoint.sin_port),
    };
}

sockaddr_in ToSockaddr(const tailgate::wgengine::magicsock::Endpoint& endpoint)
{
    sockaddr_in result{};
    result.sin_family = AF_INET;
    result.sin_addr.s_addr = htonl(endpoint.Address);
    result.sin_port = htons(endpoint.Port);
    return result;
}

struct DerpRuntime
{
    int Region = 0;
    std::string Host;
    std::unique_ptr<DerpWorker> Worker;
};

constexpr std::size_t MaximumPendingPacketsPerPeer = 1024;
constexpr std::size_t MaximumPendingBytesPerPeer = 4U * 1024U * 1024U;
constexpr std::size_t MaximumPacketsPerDescriptorCycle = 16;
constexpr auto DataplaneMaintenanceInterval = std::chrono::seconds(1);
constexpr auto StatusRefreshInterval = std::chrono::seconds(10);
constexpr auto ControlSilenceTimeout = std::chrono::minutes(2);
std::atomic<int> RelayHostControlFd = -1;
constexpr auto RelayHeartbeatInterval = std::chrono::seconds(20);
constexpr auto HandshakeRetryInterval = std::chrono::seconds(5);
constexpr auto DataplaneSlowSection = std::chrono::milliseconds(50);
constexpr auto PendingDnsTimeout = std::chrono::seconds(10);
constexpr auto PingRetryInterval = std::chrono::seconds(1);
constexpr int TailgateMtu = 1280;
constexpr int FunnelPeerApiPort = 41112;
constexpr int ExposeLocalPort = 41113;
constexpr std::size_t RelayPacketBufferSize = 4096;
constexpr std::size_t RelayNetworkMapBufferSize = 1024U * 1024U;
constexpr int ReloadWaitAttempts = 1200;
constexpr useconds_t ReloadWaitIntervalMicros = 100000;
constexpr int StunAttempts = 30;
constexpr auto StunPollInterval = std::chrono::milliseconds(100);

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

tailgate::net::stun::TransactionId GenerateStunTransactionId()
{
    tailgate::net::stun::TransactionId result{};
    std::random_device random;
    for (std::uint8_t& byte : result)
    {
        byte = static_cast<std::uint8_t>(random() & 0xffU);
    }
    return result;
}

sockaddr_in ResolveIpv4UdpEndpoint(const std::string& host, int port)
{
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    addrinfo* result = nullptr;
    const std::string service = std::format("{}", port);
    const int rc = getaddrinfo(host.c_str(), service.c_str(), &hints, &result);
    if (rc != 0)
    {
        throw std::runtime_error(
            std::format("failed to resolve STUN host {}: {}", host, gai_strerror(rc)));
    }
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> entries(result, freeaddrinfo);
    return *reinterpret_cast<sockaddr_in*>(entries->ai_addr);
}

std::optional<std::string> QueryStunEndpoint(int fd, const std::string& host, int port)
{
    const tailgate::net::stun::TransactionId transactionId = GenerateStunTransactionId();
    const std::vector<std::uint8_t> request =
        tailgate::net::stun::BuildBindingRequest(transactionId);
    const sockaddr_in endpoint = ResolveIpv4UdpEndpoint(host, port);
    SendUdp(fd, endpoint, request);

    for (int attempt = 0; attempt < StunAttempts; ++attempt)
    {
        sockaddr_in source{};
        const std::vector<std::uint8_t> response = ReceiveUdp(fd, &source);
        if (!response.empty())
        {
            if (std::optional<std::string> mapped =
                    tailgate::net::stun::ParseMappedIpv4Endpoint(response, transactionId))
            {
                return mapped;
            }
        }
        std::this_thread::sleep_for(StunPollInterval);
    }
    return std::nullopt;
}

std::string DisplayName(std::string name)
{
    if (!name.empty() && name.back() == '.')
    {
        name.pop_back();
    }
    const std::size_t dot = name.find('.');
    return name.substr(0, dot);
}

void PrintFunnelAvailability(const tailgate::linux_frontend::DaemonStatus& status,
                             const tailgate::cli::FunnelOptions& options,
                             bool background)
{
    const std::string magicName = status.Domain.empty()
                                      ? status.Hostname
                                      : std::format("{}.{}", status.Hostname, status.Domain);
    const std::string port = options.Port == 443 ? "" : std::format(":{}", options.Port);
    std::cout << "Available on the internet:\n\n";
    std::cout << std::format("https://{}{}/\n", magicName, port);
    std::cout << std::format("|-- proxy http://127.0.0.1:{}\n\n", options.LocalPort);
    if (background)
    {
        std::cout << "Funnel started and running in the background.\n";
        std::cout << std::format("To disable the proxy, run: tailgate funnel --https={} off\n",
                                 options.Port);
    }
    else
    {
        std::cout << "Press Ctrl+C to exit.\n";
    }
}

std::string CapabilitySummary(const std::vector<std::string>& capabilities)
{
    if (capabilities.empty())
    {
        return "none";
    }
    return boost::algorithm::join(capabilities, ", ");
}

std::string FeatureEnablementSummary(const tailgate::control::client::FeatureEnablement& enablement)
{
    std::string result;
    if (!enablement.Text.empty())
    {
        result += enablement.Text;
        if (enablement.Text.back() != '\n')
        {
            result += '\n';
        }
    }
    if (!enablement.Url.empty())
    {
        result += enablement.Url;
        if (enablement.Url.back() != '\n')
        {
            result += '\n';
        }
    }
    if (enablement.ShouldWait)
    {
        result += "Open the URL above to enable Funnel, then retry the command.";
    }
    else if (!enablement.Complete)
    {
        result += "Funnel is not enabled for this node.";
    }
    return result;
}

tailgate::linux_frontend::DaemonStatus RequireRunningDaemon()
{
    const auto existing = tailgate::linux_frontend::ReadDaemonStatus();
    if (!existing || !tailgate::linux_frontend::IsProcessRunning(existing->ProcessId))
    {
        throw std::runtime_error("Tailgate is not running");
    }
    return *existing;
}

void ReloadDaemon(pid_t pid)
{
    if (kill(pid, SIGUSR1) != 0)
    {
        throw std::runtime_error("failed to reload Tailgate settings");
    }
}

tailgate::linux_frontend::DaemonStatus
WaitForDaemonReload(pid_t pid, const std::string& ignoredError = {}, bool interruptible = false)
{
    const std::uint64_t targetRevision = tailgate::linux_frontend::ReadSettings()
                                             .value_or(tailgate::linux_frontend::SettingsState{})
                                             .Revision;
    tailgate::linux_frontend::DaemonStatus latest;
    for (int attempt = 0; attempt < ReloadWaitAttempts; ++attempt)
    {
        if (interruptible && StopRequested)
        {
            throw std::runtime_error("settings update interrupted");
        }
        usleep(ReloadWaitIntervalMicros);
        latest = RequireRunningDaemon();
        if (latest.ProcessId != pid)
        {
            throw std::runtime_error("Tailgate daemon restarted during reload");
        }
        if (latest.ConfigurationRevision < targetRevision)
        {
            continue;
        }
        if (!latest.Error.empty() && latest.Error != ignoredError)
        {
            throw std::runtime_error(latest.Error);
        }
        if (latest.Online)
        {
            return latest;
        }
    }
    if (!latest.Error.empty())
    {
        throw std::runtime_error(latest.Error);
    }
    throw std::runtime_error("Tailgate daemon did not finish applying settings");
}

std::string AccidentalUpMessage(const tailgate::linux_frontend::SettingsState& settings)
{
    std::string command = "\n\n        tailgate up";
    if (!settings.ExitNode.empty())
    {
        command += std::format(" --exit-node={}", settings.ExitNode);
    }
    if (!settings.AcceptDns)
    {
        command += " --accept-dns=false";
    }
    if (!settings.TailgateUrl.empty())
    {
        command += std::format(" --tailgate={}", settings.TailgateUrl);
    }
    return std::format("changing settings via 'tailgate up' requires mentioning all\n"
                       "non-default flags. To proceed, either re-run your command with --reset or\n"
                       "use the command below to explicitly mention the current value of\n"
                       "all non-default settings:{}",
                       command);
}

tailgate::linux_frontend::SettingsState
ApplyUpOptions(const tailgate::linux_frontend::SettingsState& current,
               const tailgate::cli::UpOptions& options)
{
    const bool anyPreference = options.HostnameSet || options.AcceptDnsSet || options.ExitNodeSet ||
                               options.TailgateUrlSet || options.Reset;
    if (!anyPreference)
    {
        return current;
    }
    if (!options.Reset && ((!options.ExitNodeSet && !current.ExitNode.empty()) ||
                           (!options.AcceptDnsSet && !current.AcceptDns) ||
                           (!options.TailgateUrlSet && !current.TailgateUrl.empty())))
    {
        throw std::runtime_error(AccidentalUpMessage(current));
    }
    tailgate::linux_frontend::SettingsState result = current;
    result.ExitNode = options.ExitNodeSet ? options.ExitNode : "";
    result.AcceptDns = options.AcceptDnsSet ? options.AcceptDns : true;
    result.TailgateUrl = options.TailgateUrlSet ? options.TailgateUrl : "";
    if (options.HostnameSet)
    {
        result.Hostname = options.Hostname;
    }
    return result;
}

std::uint32_t Ipv4ToHostOrder(const std::string& ip)
{
    const auto address = tailgate::net::packet::ParseIpv4(ip);
    if (!address)
    {
        throw std::runtime_error("invalid IPv4 address: " + ip);
    }
    return *address;
}

std::string FirstIpv6Address(const std::vector<std::string>& addresses)
{
    const auto found = std::find_if(addresses.begin(),
                                    addresses.end(),
                                    [](const std::string& address)
                                    {
                                        return address.find(':') != std::string::npos;
                                    });
    return found == addresses.end() ? "" : *found;
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

struct LiveControlSession
{
    std::unique_ptr<tailgate::linux_frontend::ControlStream> Stream;
    std::unique_ptr<tailgate::control::client::ControlClient> Control;
    tailgate::types::netmap::NetworkConfig InitialNetwork;
};

void StartTunnel(
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
    tailgate::control::client::ControlClient* control,
    int controlFd,
    int advertisedUdpFd,
    std::function<std::unique_ptr<LiveControlSession>()> reconnectControl,
    tailgate::linux_frontend::DaemonStatus& status,
    int& readyFd,
    int packetFd = -1,
    bool configureHost = true,
    bool persistStatus = true,
    bool encryptedPacketTransport = false,
    int networkMapFd = -1,
    std::function<void(const tailgate::types::netmap::NetworkConfig&)> networkMapUpdated = {},
    tailgate::derp::DerpClient::Authenticator derpAuthenticator = {})
{
    std::string interfaceName = "tailgate0";
    status.Domain = domain;
    if (!selfDnsName.empty())
    {
        const std::size_t dot = selfDnsName.find('.');
        status.Hostname = dot == std::string::npos ? selfDnsName : selfDnsName.substr(0, dot);
    }
    const std::string underlayInterface = DefaultRouteInterface();
    const std::uint32_t underlayAddress = InterfaceIpv4Address(underlayInterface);
    if (advertisedUdpFd < 0)
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

    UniqueFd tun(packetFd >= 0 ? dup(packetFd) : OpenTun(interfaceName).Release());
    if (tun.Fd < 0)
    {
        throw std::runtime_error("failed to duplicate relay packet descriptor");
    }
    const int tunFlags = fcntl(tun.Fd, F_GETFL, 0);
    if (tunFlags < 0 || fcntl(tun.Fd, F_SETFL, tunFlags | O_NONBLOCK) != 0)
    {
        throw std::runtime_error("failed to configure packet descriptor as nonblocking");
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
        AddRoute(interfaceName,
                 Ipv4Prefix{.Network = Ipv4ToHostOrder("100.64.0.0"), .PrefixLength = 10});
        AddRoute(interfaceName,
                 Ipv4Prefix{.Network = Ipv4ToHostOrder(currentDnsResolver), .PrefixLength = 32});
    }
    std::vector<std::unique_ptr<tailgate::linux_frontend::LinuxPeerApiServer>> peerApiServers;
    if (configureHost && tailgate::serve::IsEnabled(funnel))
    {
        const std::string funnelHost =
            !selfDnsName.empty() ? selfDnsName
                                 : (domain.empty() ? status.Hostname
                                                   : std::format("{}.{}", status.Hostname, domain));
        const std::string funnelTarget = tailgate::serve::TargetHostPort(funnelHost, funnel.Port);
        peerApiServers.push_back(
            std::make_unique<tailgate::linux_frontend::LinuxPeerApiServer>(selfIp,
                                                                           FunnelPeerApiPort,
                                                                           funnelTarget,
                                                                           funnel.LocalPort,
                                                                           funnelCertificatePem,
                                                                           funnelPrivateKeyPem));
        if (!selfIpv6.empty())
        {
            peerApiServers.push_back(std::make_unique<tailgate::linux_frontend::LinuxPeerApiServer>(
                selfIpv6,
                FunnelPeerApiPort,
                funnelTarget,
                funnel.LocalPort,
                funnelCertificatePem,
                funnelPrivateKeyPem));
        }
    }

    std::unique_ptr<tailgate::wgengine::wireguard::WireGuardTunnel> tunnel;
    if (!encryptedPacketTransport)
    {
        tunnel = std::make_unique<tailgate::wgengine::wireguard::WireGuardTunnel>(nodePrivateKey);
    }
    std::unique_ptr<tailgate::disco::Disco> disco;
    if (!encryptedPacketTransport)
    {
        disco = std::make_unique<tailgate::disco::Disco>(discoPrivateKey, nodePublicKey);
    }

    std::deque<PeerRuntime> peers;
    auto buildPeerRuntime = [&](const TailPeer& config) -> std::optional<PeerRuntime>
    {
        std::vector<std::uint8_t> publicKeyBytes =
            tailgate::crypto::HexToBytes(config.Key.substr(8));
        if (publicKeyBytes.size() != tailgate::wgengine::wireguard::WireGuardTunnel::Key{}.size())
        {
            return std::nullopt;
        }
        tailgate::wgengine::wireguard::WireGuardTunnel::Key publicKey{};
        std::copy(publicKeyBytes.begin(), publicKeyBytes.end(), publicKey.begin());
        PeerRuntime runtime;
        runtime.Config = config;
        if (tunnel)
        {
            runtime.TunnelPeer = tunnel->AddPeer(publicKey);
        }
        runtime.PublicKey = publicKey;
        if (config.DiscoKey.rfind("discokey:", 0) == 0)
        {
            const auto discoKey = tailgate::crypto::HexToBytes(config.DiscoKey.substr(9));
            if (discoKey.size() == runtime.DiscoPublicKey.size())
            {
                std::copy(discoKey.begin(), discoKey.end(), runtime.DiscoPublicKey.begin());
                runtime.HasDiscoKey = true;
            }
        }
        runtime.Socket = OpenUdpSocket(underlayInterface);
        return runtime;
    };
    for (const TailPeer& config : peerConfigs)
    {
        std::optional<PeerRuntime> runtime = buildPeerRuntime(config);
        if (runtime)
        {
            if (config.IngressEnabled || config.WireIngress || config.PeerApi4Port != 0 ||
                config.PeerApi6Port != 0)
            {
                tailgate::base::Log(
                    tailgate::base::LogLevel::Info,
                    "control",
                    std::format("peer advertises ingress name={} version={} ingress={} "
                                "wire-ingress={} peerapi4={} peerapi6={}",
                                config.Name,
                                config.ClientVersion,
                                config.IngressEnabled ? 1 : 0,
                                config.WireIngress ? 1 : 0,
                                config.PeerApi4Port,
                                config.PeerApi6Port));
            }
            peers.push_back(std::move(*runtime));
        }
    }

    if (peers.empty())
    {
        throw std::runtime_error("netmap did not contain usable IPv4 peers");
    }

    std::vector<DerpRuntime> derps;
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
        if (region == 0 || host.empty())
        {
            throw std::runtime_error("peer has no usable DERP region");
        }
        tailgate::base::Log(
            tailgate::base::LogLevel::Info,
            "derp",
            std::format(
                "connecting region={} host={}{}", region, host, preferred ? " preferred" : ""));
        derps.push_back(DerpRuntime{.Region = region,
                                    .Host = host,
                                    .Worker = std::make_unique<DerpWorker>(host,
                                                                           underlayInterface,
                                                                           nodePrivateKey,
                                                                           nodePublicKey,
                                                                           preferred,
                                                                           derpAuthenticator)});
        return derps.size() - 1;
    };
    auto ensureDerp = [&](int region, const std::string& host, bool preferred) -> DerpWorker&
    {
        return *derps[ensureDerpIndex(region, host, preferred)].Worker;
    };
    (void)ensureDerp(derpRegion, derpHost, true);
    for (const PeerRuntime& peer : peers)
    {
        if (peer.Config.DerpRegion != 0 && !peer.Config.DerpHost.empty())
        {
            (void)ensureDerp(peer.Config.DerpRegion, peer.Config.DerpHost, false);
        }
    }
    if (configureHost && acceptDns)
    {
        WriteResolver("127.0.0.1", currentDnsDomains);
    }
    auto derpForPeer = [&](const PeerRuntime& peer) -> DerpWorker&
    {
        auto found = std::find_if(derps.begin(),
                                  derps.end(),
                                  [&](const DerpRuntime& derp)
                                  {
                                      return derp.Region == peer.Config.DerpRegion;
                                  });
        if (found != derps.end())
        {
            return *found->Worker;
        }
        return *derps.front().Worker;
    };
    auto sendRelay = [&](const PeerRuntime& peer,
                         const std::vector<std::uint8_t>& packet,
                         DerpWorker::Priority priority = DerpWorker::Priority::Data)
    {
        derpForPeer(peer).Send(peer.PublicKey, packet, priority);
    };

    std::vector<TailPeer> routablePeers;
    auto rebuildRoutablePeers = [&]()
    {
        routablePeers.clear();
        routablePeers.reserve(peers.size());
        for (const PeerRuntime& peer : peers)
        {
            routablePeers.push_back(peer.Config);
        }
    };
    rebuildRoutablePeers();

    PeerRuntime* exitPeer = nullptr;
    std::optional<std::size_t> exitPeerIndex;
    if (!exitNode.empty())
    {
        exitPeerIndex = tailgate::types::netmap::FindExitNode(routablePeers, exitNode, true);
        if (!exitPeerIndex)
        {
            throw std::runtime_error("exit node was not found in the network map: " + exitNode);
        }
        exitPeer = &peers[*exitPeerIndex];
        if (configureHost)
        {
            AddRoute(interfaceName,
                     Ipv4Prefix{.Network = Ipv4ToHostOrder("0.0.0.0"), .PrefixLength = 1});
            AddRoute(interfaceName,
                     Ipv4Prefix{.Network = Ipv4ToHostOrder("128.0.0.0"), .PrefixLength = 1});
        }
        tailgate::base::Log(tailgate::base::LogLevel::Info,
                            "tunnel",
                            std::format("exit node={} address={}",
                                        exitPeer->Config.Name,
                                        exitPeer->Config.Address));
    }

    auto findRoute = [&](std::uint32_t destination) -> PeerRuntime*
    {
        const auto index =
            tailgate::types::netmap::FindRoute(routablePeers, destination, exitPeerIndex);
        return index ? &peers[*index] : nullptr;
    };
    auto findIpv6Route = [&](const std::string& destination) -> PeerRuntime*
    {
        auto found = std::find_if(peers.begin(),
                                  peers.end(),
                                  [&](const PeerRuntime& peer)
                                  {
                                      return std::find(peer.Config.Addresses.begin(),
                                                       peer.Config.Addresses.end(),
                                                       destination) != peer.Config.Addresses.end();
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
    const auto peerSocket = [&](const PeerRuntime& peer)
    {
        return peer.UseAdvertisedSocket ? advertisedUdpFd : peer.Socket.Fd;
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

    auto startDirectProbe = [&](PeerRuntime& peer)
    {
        if (!disco || !peer.HasDiscoKey || peer.Path.HasDirectPath() ||
            !peer.Path.TryBeginProbe(std::chrono::steady_clock::now()))
        {
            return;
        }
        peer.DirectProbeTransaction = disco->NewTransactionId();
        sendRelay(peer,
                  disco->BuildCallMeMaybe(peer.DiscoPublicKey,
                                          {{underlayAddress, SocketPort(advertisedUdpFd)}}),
                  DerpWorker::Priority::Control);
        const std::vector<std::uint8_t> ping =
            disco->BuildPing(peer.DiscoPublicKey, peer.DirectProbeTransaction);
        for (const std::string& endpoint : peer.Config.Endpoints)
        {
            if (const auto candidate = TryParseIpv4Endpoint(endpoint))
            {
                SendUdp(advertisedUdpFd, *candidate, ping);
            }
        }
    };

    auto queueOutgoing = [&](PeerRuntime& peer, std::vector<std::uint8_t> packet)
    {
        const auto now = std::chrono::steady_clock::now();
        ++peer.UdpBackpressureEvents;
        if (peer.LastBackpressureLog == std::chrono::steady_clock::time_point{} ||
            now - peer.LastBackpressureLog >= std::chrono::seconds(1))
        {
            peer.LastBackpressureLog = now;
            tailgate::base::Log(tailgate::base::LogLevel::Debug,
                                "tunnel",
                                std::format("UDP backpressure peer={} queued={} bytes={} events={}",
                                            peer.Config.Name,
                                            peer.OutgoingPackets.size(),
                                            peer.OutgoingBytes,
                                            peer.UdpBackpressureEvents));
        }
        while (!peer.OutgoingPackets.empty() &&
               (peer.OutgoingPackets.size() >= MaximumPendingPacketsPerPeer ||
                peer.OutgoingBytes + packet.size() > MaximumPendingBytesPerPeer))
        {
            peer.OutgoingBytes -= peer.OutgoingPackets.front().size();
            peer.OutgoingPackets.pop_front();
            tailgate::base::Log(tailgate::base::LogLevel::Warning,
                                "tunnel",
                                "outgoing packet limit reached for peer=" + peer.Config.Name);
        }
        if (packet.size() <= MaximumPendingBytesPerPeer)
        {
            peer.OutgoingBytes += packet.size();
            peer.OutgoingPackets.push_back(std::move(packet));
        }
    };
    auto flushOutgoing = [&](PeerRuntime& peer)
    {
        while (peer.Path.HasDirectPath() && !peer.OutgoingPackets.empty())
        {
            const sockaddr_in endpoint = ToSockaddr(*peer.Path.DirectEndpoint());
            if (!TrySendUdp(peerSocket(peer), endpoint, peer.OutgoingPackets.front()))
            {
                return;
            }
            peer.OutgoingBytes -= peer.OutgoingPackets.front().size();
            peer.OutgoingPackets.pop_front();
        }
    };
    auto sendPeer = [&sendRelay, &queueOutgoing, &flushOutgoing, &peerSocket](
                        PeerRuntime& peer,
                        const std::vector<std::uint8_t>& packet,
                        bool expectResponse = true,
                        DerpWorker::Priority priority = DerpWorker::Priority::Data)
    {
        peer.TxBytes += packet.size();
        if (peer.Path.HasDirectPath())
        {
            flushOutgoing(peer);
            if (peer.OutgoingPackets.empty())
            {
                const sockaddr_in endpoint = ToSockaddr(*peer.Path.DirectEndpoint());
                if (!TrySendUdp(peerSocket(peer), endpoint, packet))
                {
                    queueOutgoing(peer, packet);
                }
            }
            else
            {
                queueOutgoing(peer, packet);
            }
            if (expectResponse)
            {
                peer.Path.MarkDirectSend(std::chrono::steady_clock::now());
            }
        }
        else
        {
            sendRelay(peer, packet, priority);
        }
    };

    auto sendHandshake = [&](PeerRuntime& peer)
    {
        const auto now = std::chrono::steady_clock::now();
        if (peer.LastHandshake != std::chrono::steady_clock::time_point{} &&
            now - peer.LastHandshake < HandshakeRetryInterval)
        {
            return;
        }
        const std::vector<std::uint8_t> handshake = tunnel->CreateHandshake(peer.TunnelPeer);
        peer.LastHandshake = now;
        tailgate::base::Log(
            tailgate::base::LogLevel::Debug, "tunnel", "handshake peer=" + peer.Config.Name);
        sendRelay(peer, handshake, DerpWorker::Priority::Control);
        if (peer.Path.HasDirectPath())
        {
            SendUdp(peerSocket(peer), ToSockaddr(*peer.Path.DirectEndpoint()), handshake);
        }
        else
        {
            for (const std::string& endpoint : peer.Config.Endpoints)
            {
                if (const auto candidate = TryParseIpv4Endpoint(endpoint))
                {
                    SendUdp(advertisedUdpFd, *candidate, handshake);
                }
            }
        }
    };

    PeerRuntime* dnsPeer = findRoute(Ipv4ToHostOrder(currentDnsResolver));
    if (dnsPeer == nullptr)
    {
        throw std::runtime_error("netmap does not contain a route to the DNS resolver");
    }
    if (tunnel)
    {
        sendHandshake(*dnsPeer);
        if (exitPeer != nullptr && exitPeer != dnsPeer)
        {
            sendHandshake(*exitPeer);
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
        if (peer.Name.empty())
        {
            continue;
        }
        tailgate::linux_frontend::PeerStatus peerStatus;
        peerStatus.Address = peer.Address;
        peerStatus.Hostname = DisplayName(peer.Name);
        peerStatus.OperatingSystem = peer.OperatingSystem;
        peerStatus.Relay =
            peer.DerpCode.empty() ? std::format("derp-{}", peer.DerpRegion) : peer.DerpCode;
        peerStatus.Online = peer.Online;
        peerStatus.ExitNodeOption = peer.ExitNodeOption;
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
    tailgate::linux_frontend::LinuxStatusWriter statusWriter;
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
    std::deque<std::vector<std::uint8_t>> pendingTunPackets;
    std::size_t pendingTunBytes = 0;
    auto flushTun = [&]()
    {
        while (!pendingTunPackets.empty())
        {
            const std::vector<std::uint8_t>& packet = pendingTunPackets.front();
            const ssize_t written = write(tun.Fd, packet.data(), packet.size());
            if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            {
                return;
            }
            if (written < 0 || static_cast<std::size_t>(written) != packet.size())
            {
                throw std::runtime_error("TUN write failed: " + std::string(std::strerror(errno)));
            }
            pendingTunBytes -= packet.size();
            pendingTunPackets.pop_front();
        }
    };
    auto queueTun = [&](std::vector<std::uint8_t> packet)
    {
        while (!pendingTunPackets.empty() &&
               (pendingTunPackets.size() >= MaximumPendingPacketsPerPeer ||
                pendingTunBytes + packet.size() > MaximumPendingBytesPerPeer))
        {
            pendingTunBytes -= pendingTunPackets.front().size();
            pendingTunPackets.pop_front();
            tailgate::base::Log(
                tailgate::base::LogLevel::Warning, "tunnel", "outbound TUN queue limit reached");
        }
        if (packet.size() <= MaximumPendingBytesPerPeer)
        {
            pendingTunBytes += packet.size();
            pendingTunPackets.push_back(std::move(packet));
            flushTun();
        }
    };
    const auto forwardEncryptedPacket = [&](const PeerRuntime& peer,
                                            const std::vector<std::uint8_t>& packet,
                                            bool isDisco,
                                            const std::optional<sockaddr_in>& source)
    {
        tailgate::hosted::PeerPacket forwarded;
        forwarded.Peer = peer.PublicKey;
        forwarded.Payload = packet;
        forwarded.Disco = isDisco;
        if (source)
        {
            forwarded.EndpointAddress = ntohl(source->sin_addr.s_addr);
            forwarded.EndpointPort = ntohs(source->sin_port);
        }
        queueTun(tailgate::hosted::EncodePeerPacket(forwarded));
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

    struct ControlUpdateWorker
    {
        tailgate::control::client::ControlClient* Control = nullptr;
        std::atomic<int> ControlFd = -1;
        UniqueFd Event;
        std::mutex Mutex;
        std::deque<tailgate::types::netmap::NetworkConfig> Updates;
        std::exception_ptr Error;
        std::atomic_bool Stop = false;
        std::thread Thread;
        std::function<std::unique_ptr<LiveControlSession>()> Reconnect;
        std::unique_ptr<LiveControlSession> OwnedControl;
        std::atomic<int>* PublishedControlFd = nullptr;

        ControlUpdateWorker(tailgate::control::client::ControlClient* controlClient,
                            int fd,
                            std::function<std::unique_ptr<LiveControlSession>()> reconnect,
                            std::atomic<int>* publishedControlFd)
            : Control(controlClient),
              ControlFd(fd),
              Event(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK)),
              Reconnect(std::move(reconnect)),
              PublishedControlFd(publishedControlFd)
        {
            if (Control == nullptr || ControlFd.load() < 0)
            {
                Event.Reset();
                return;
            }
            if (Event.Fd < 0)
            {
                throw std::runtime_error("eventfd failed: " + std::string(std::strerror(errno)));
            }
            if (PublishedControlFd != nullptr)
            {
                PublishedControlFd->store(fd);
            }
            Thread = std::thread(
                [this]()
                {
                    Run();
                });
        }

        ~ControlUpdateWorker()
        {
            Stop = true;
            const int controlFd = ControlFd.load();
            if (PublishedControlFd != nullptr)
            {
                int expected = controlFd;
                PublishedControlFd->compare_exchange_strong(expected, -1);
            }
            if (controlFd >= 0)
            {
                shutdown(controlFd, SHUT_RDWR);
            }
            if (Thread.joinable())
            {
                Thread.join();
            }
        }

        [[nodiscard]] bool Active() const
        {
            return Event.Fd >= 0;
        }

        void Wake()
        {
            std::uint64_t value = 1;
            if (write(Event.Fd, &value, sizeof(value)) < 0 && errno != EAGAIN &&
                errno != EWOULDBLOCK)
            {
                Stop = true;
            }
        }

        void Run()
        {
            int retrySeconds = 1;
            while (!Stop)
            {
                try
                {
                    UniqueFd silenceDeadline = CreateDeadlineTimerFd(ControlSilenceTimeout);
                    std::array<pollfd, 2> descriptors{
                        pollfd{.fd = ControlFd.load(),
                               .events = POLLIN | POLLERR | POLLHUP,
                               .revents = 0},
                        pollfd{.fd = silenceDeadline.Fd, .events = POLLIN, .revents = 0}};
                    while (!Stop)
                    {
                        for (pollfd& descriptor : descriptors)
                        {
                            descriptor.revents = 0;
                        }
                        const int ready = poll(descriptors.data(), descriptors.size(), -1);
                        if (ready < 0 && errno == EINTR)
                        {
                            continue;
                        }
                        if (ready < 0)
                        {
                            throw std::runtime_error("control poll failed: " +
                                                     std::string(std::strerror(errno)));
                        }
                        if ((descriptors[1].revents & POLLIN) != 0)
                        {
                            throw std::runtime_error("control stream received no keepalive");
                        }
                        if ((descriptors[0].revents & (POLLERR | POLLHUP)) != 0)
                        {
                            throw std::runtime_error("control stream closed");
                        }
                        if ((descriptors[0].revents & POLLIN) == 0)
                        {
                            continue;
                        }
                        ResetDeadlineTimerFd(silenceDeadline.Fd, ControlSilenceTimeout);
                        bool changed = false;
                        while (std::optional<tailgate::types::netmap::NetworkConfig> update =
                                   Control->PollNetworkMap())
                        {
                            std::lock_guard<std::mutex> lock(Mutex);
                            Updates.push_back(std::move(*update));
                            changed = true;
                        }
                        if (changed)
                        {
                            Wake();
                        }
                    }
                }
                catch (const std::exception& error)
                {
                    if (Stop)
                    {
                        return;
                    }
                    if (!Reconnect)
                    {
                        std::lock_guard<std::mutex> lock(Mutex);
                        Error = std::current_exception();
                        Wake();
                        return;
                    }
                    tailgate::base::Log(tailgate::base::LogLevel::Warning,
                                        "control",
                                        std::format("stream interrupted: {}; reconnecting without "
                                                    "stopping the data plane",
                                                    error.what()));
                }
                while (!Stop)
                {
                    try
                    {
                        std::unique_ptr<LiveControlSession> replacement = Reconnect();
                        tailgate::types::netmap::NetworkConfig initialNetwork =
                            std::move(replacement->InitialNetwork);
                        Control = replacement->Control.get();
                        ControlFd.store(replacement->Stream->NativeHandle());
                        if (PublishedControlFd != nullptr)
                        {
                            PublishedControlFd->store(ControlFd.load());
                        }
                        OwnedControl = std::move(replacement);
                        {
                            std::lock_guard<std::mutex> lock(Mutex);
                            Updates.push_back(std::move(initialNetwork));
                        }
                        Wake();
                        retrySeconds = 1;
                        tailgate::base::Log(
                            tailgate::base::LogLevel::Info,
                            "control",
                            "stream reconnected with a fresh network map; data plane "
                            "remained active");
                        break;
                    }
                    catch (const std::exception& error)
                    {
                        tailgate::base::Log(
                            tailgate::base::LogLevel::Warning,
                            "control",
                            std::format("reconnect failed: {}; retrying in {} seconds",
                                        error.what(),
                                        retrySeconds));
                    }
                    for (int elapsed = 0; elapsed < retrySeconds && !Stop; ++elapsed)
                    {
                        std::this_thread::sleep_for(std::chrono::seconds(1));
                    }
                    retrySeconds = std::min(retrySeconds * 2, 30);
                }
            }
        }

        std::deque<tailgate::types::netmap::NetworkConfig> TakeUpdates()
        {
            std::lock_guard<std::mutex> lock(Mutex);
            if (Error)
            {
                std::rethrow_exception(Error);
            }
            std::deque<tailgate::types::netmap::NetworkConfig> result;
            result.swap(Updates);
            return result;
        }
    };

    auto queueOrSend = [&](PeerRuntime& peer, std::vector<std::uint8_t> plaintext)
    {
        if (tunnel->HasSession(peer.TunnelPeer))
        {
            sendPeer(peer, tunnel->Encrypt(peer.TunnelPeer, plaintext));
            return;
        }
        while (!peer.PendingPackets.empty() &&
               (peer.PendingPackets.size() >= MaximumPendingPacketsPerPeer ||
                peer.PendingBytes + plaintext.size() > MaximumPendingBytesPerPeer))
        {
            peer.PendingBytes -= peer.PendingPackets.front().size();
            peer.PendingPackets.pop_front();
            tailgate::base::Log(tailgate::base::LogLevel::Warning,
                                "tunnel",
                                "pending packet limit reached for peer=" + peer.Config.Name);
        }
        if (plaintext.size() <= MaximumPendingBytesPerPeer)
        {
            peer.PendingBytes += plaintext.size();
            peer.PendingPackets.push_back(std::move(plaintext));
        }
        sendHandshake(peer);
        startDirectProbe(peer);
    };
    auto flushPending = [&](PeerRuntime& peer)
    {
        while (tunnel->HasSession(peer.TunnelPeer) && !peer.PendingPackets.empty())
        {
            std::vector<std::uint8_t> plaintext = std::move(peer.PendingPackets.front());
            peer.PendingPackets.pop_front();
            peer.PendingBytes -= plaintext.size();
            sendPeer(peer, tunnel->Encrypt(peer.TunnelPeer, plaintext));
        }
    };
    auto handleNodeControlPacket = [&](PeerRuntime& peer, const std::vector<std::uint8_t>& packet)
    {
        if (configureHost)
        {
            if (const auto tsmpPong =
                    tailgate::net::packet::BuildTsmpPong(packet, FunnelPeerApiPort))
            {
                tailgate::base::Log(tailgate::base::LogLevel::Info,
                                    "peerapi",
                                    std::format("TSMP probe from peer={} address={}",
                                                peer.Config.Name,
                                                peer.Config.Address));
                queueOrSend(peer, *tsmpPong);
                return true;
            }
        }
        return false;
    };
    auto drainTunInput = [&]()
    {
        for (std::size_t iteration = 0; iteration < MaximumPacketsPerDescriptorCycle; ++iteration)
        {
            std::vector<std::uint8_t> packet(4096);
            const ssize_t bytesRead = read(tun.Fd, packet.data(), packet.size());
            if (bytesRead < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            {
                break;
            }
            if (bytesRead < 0)
            {
                throw std::runtime_error("TUN read failed: " + std::string(std::strerror(errno)));
            }
            packet.resize(static_cast<std::size_t>(bytesRead));
            if (encryptedPacketTransport)
            {
                const tailgate::hosted::PeerPacket transportPacket =
                    tailgate::hosted::DecodePeerPacket(packet);
                PeerRuntime* peer = peerForKey(transportPacket.Peer);
                if (peer == nullptr)
                {
                    tailgate::base::Log(tailgate::base::LogLevel::Warning,
                                        "relay",
                                        "dropping encrypted packet for unknown peer");
                    continue;
                }
                if (transportPacket.Disco)
                {
                    tailgate::base::Log(
                        tailgate::base::LogLevel::Trace,
                        "relay",
                        std::format(
                            "forwarding hosted disco packet peer={} endpoint={}:{}",
                            peer->Config.Name,
                            tailgate::net::packet::FormatIpv4(transportPacket.EndpointAddress),
                            transportPacket.EndpointPort));
                    if (transportPacket.EndpointAddress != 0 && transportPacket.EndpointPort != 0)
                    {
                        sockaddr_in endpoint{};
                        endpoint.sin_family = AF_INET;
                        endpoint.sin_addr.s_addr = htonl(transportPacket.EndpointAddress);
                        endpoint.sin_port = htons(transportPacket.EndpointPort);
                        SendUdp(peerSocket(*peer), endpoint, transportPacket.Payload);
                        (void)peer->Path.MarkDirect(ToMagicsockEndpoint(endpoint));
                    }
                    else
                    {
                        sendRelay(*peer, transportPacket.Payload, DerpWorker::Priority::Control);
                        for (const std::string& endpoint : peer->Config.Endpoints)
                        {
                            if (const auto candidate = TryParseIpv4Endpoint(endpoint))
                            {
                                SendUdp(peerSocket(*peer), *candidate, transportPacket.Payload);
                            }
                        }
                    }
                    continue;
                }
                sendPeer(*peer,
                         transportPacket.Payload,
                         true,
                         transportPacket.Control ? DerpWorker::Priority::Control
                                                 : DerpWorker::Priority::Data);
                continue;
            }
            const std::optional<std::uint32_t> destination =
                tailgate::net::packet::Ipv4Destination(packet);
            if (destination)
            {
                PeerRuntime* peer = findRoute(*destination);
                if (!peer)
                {
                    tailgate::base::Log(tailgate::base::LogLevel::Warning,
                                        "tunnel",
                                        "dropping unroutable packet to " +
                                            tailgate::net::packet::FormatIpv4(*destination));
                    continue;
                }
                queueOrSend(*peer, std::move(packet));
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
    auto selectDnsResolver = [&](const std::vector<std::uint8_t>& query)
    {
        const auto name = tailgate::net::dns::DnsQueryName(query);
        const std::vector<std::string>* selected = nullptr;
        std::size_t selectedSuffixLength = 0;
        for (const auto& route : currentDnsRoutes)
        {
            if (name && route.Suffix.size() >= selectedSuffixLength &&
                tailgate::net::dns::DnsNameHasSuffix(*name, route.Suffix))
            {
                selected = &route.Resolvers;
                selectedSuffixLength = route.Suffix.size();
            }
        }
        std::string resolver;
        if (selected != nullptr)
        {
            resolver = selected->empty() ? currentDnsResolver : selected->front();
        }
        else if (!currentDnsDefaultResolvers.empty())
        {
            resolver = currentDnsDefaultResolvers.front();
        }
        else if (!originalResolvers.empty())
        {
            resolver = originalResolvers.front();
        }
        if (!tailgate::net::packet::ParseIpv4(resolver))
        {
            throw std::runtime_error("DNS resolver transport is unsupported: " + resolver);
        }
        return resolver;
    };
    auto handleDnsResponse = [&](const std::vector<std::uint8_t>& packet)
    {
        for (auto pending = pendingDnsClients.begin(); pending != pendingDnsClients.end();
             ++pending)
        {
            auto payload = tailgate::net::packet::ExtractUdpPayload(
                packet, pending->Resolver, Ipv4ToHostOrder(selfIp), 53, pending->SourcePort);
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
        response.NodeName = pending.Peer->Config.Name;
        response.NodeAddress = pending.Peer->Config.Address;
        const std::optional<std::string> hostedPath =
            HostedPathForNode(pending.Peer->Config.NodeId);
        response.Endpoint = hostedPath.value_or(endpoint);
        response.Relay = pending.Peer->Config.DerpCode.empty()
                             ? std::format("derp-{}", pending.Peer->Config.DerpRegion)
                             : pending.Peer->Config.DerpCode;
        response.PeerApiPort = peerApiPort;
        tailgate::linux_frontend::SendPingResponse(
            pingServer.Fd, pending.Client, pending.ClientLength, response);
        pending.Peer = nullptr;
    };
    auto handlePingResponse = [&](const std::vector<std::uint8_t>& packet)
    {
        const std::optional<tailgate::net::packet::TsmpPong> pong =
            tailgate::net::packet::ParseTsmpPong(packet);
        if (!pong)
        {
            return false;
        }
        const auto pending = std::find_if(pendingPings.begin(),
                                          pendingPings.end(),
                                          [&](const PendingPing& candidate)
                                          {
                                              return candidate.Peer != nullptr && candidate.Tsmp &&
                                                     candidate.TsmpToken == pong->Token;
                                          });
        if (pending == pendingPings.end())
        {
            return true;
        }
        completePing(*pending, true, {}, pong->PeerApiPort);
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
                tailgate::net::packet::BuildTsmpPing(Ipv4ToHostOrder(selfIp),
                                                     Ipv4ToHostOrder(pending.Peer->Config.Address),
                                                     pending.TsmpToken));
            pending.LastSent = std::chrono::steady_clock::now();
            return;
        }
        const std::vector<std::uint8_t> ping =
            disco->BuildPing(pending.Peer->DiscoPublicKey, pending.Transaction);
        sendRelay(*pending.Peer, ping, DerpWorker::Priority::Control);
        for (const std::string& endpoint : pending.Peer->Config.Endpoints)
        {
            if (const auto candidate = TryParseIpv4Endpoint(endpoint))
            {
                SendUdp(advertisedUdpFd, *candidate, ping);
            }
        }
        pending.LastSent = std::chrono::steady_clock::now();
    };
    auto relayName = [](const TailPeer& peer)
    {
        return peer.DerpCode.empty() ? std::format("derp-{}", peer.DerpRegion) : peer.DerpCode;
    };
    auto updateRuntimeDiscoKey = [](PeerRuntime& peer)
    {
        peer.HasDiscoKey = false;
        peer.DiscoPublicKey = {};
        if (peer.Config.DiscoKey.rfind("discokey:", 0) != 0)
        {
            return;
        }
        const auto discoKey = tailgate::crypto::HexToBytes(peer.Config.DiscoKey.substr(9));
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
        const bool changed = peer.Path.MarkDirect(ToMagicsockEndpoint(source));
        if (changed)
        {
            tailgate::base::Log(
                tailgate::base::LogLevel::Info,
                component,
                std::format("direct peer={} endpoint={}", peer.Config.Name, endpoint));
        }
        for (auto& peerStatus : status.Peers)
        {
            if (peerStatus.Address == peer.Config.Address)
            {
                const bool statusChanged = !peerStatus.Direct || !peerStatus.Active ||
                                           !peerStatus.Online || peerStatus.Endpoint != endpoint;
                peerStatus.Direct = true;
                peerStatus.Active = true;
                peerStatus.Online = true;
                peerStatus.Endpoint = endpoint;
                if (statusChanged)
                {
                    submitStatus(status);
                }
            }
        }
    };
    auto handleDisco = [&](PeerRuntime& peer,
                           const std::vector<std::uint8_t>& packet,
                           const std::optional<sockaddr_in>& source,
                           DerpWorker* sourceDerp,
                           const tailgate::derp::DerpClient::Key* derpSource)
    {
        const auto message = disco->Parse(packet);
        if (!message || message->Sender != peer.DiscoPublicKey)
        {
            return;
        }
        if (message->Type == tailgate::disco::Disco::MessageType::CallMeMaybe)
        {
            if (derpSource == nullptr)
            {
                return;
            }
            const auto transaction = disco->NewTransactionId();
            const auto ping = disco->BuildPing(peer.DiscoPublicKey, transaction);
            for (const auto& candidate : message->Endpoints)
            {
                sockaddr_in endpoint{};
                endpoint.sin_family = AF_INET;
                endpoint.sin_addr.s_addr = htonl(candidate.Address);
                endpoint.sin_port = htons(candidate.Port);
                SendUdp(advertisedUdpFd, endpoint, ping);
            }
            tailgate::base::Log(tailgate::base::LogLevel::Debug,
                                "disco",
                                std::format("CallMeMaybe peer={} endpoints={}",
                                            peer.Config.Name,
                                            message->Endpoints.size()));
            return;
        }
        if (message->Type == tailgate::disco::Disco::MessageType::Ping)
        {
            // DERP-received pings have no UDP source; peers discard pongs with a zero source,
            // so report the Tailscale DERP magic address for the home region instead.
            const std::uint32_t sourceAddress = source
                                                    ? ntohl(source->sin_addr.s_addr)
                                                    : tailgate::disco::Disco::DerpMagicIpv4Address;
            const std::uint16_t sourcePort =
                source ? ntohs(source->sin_port) : static_cast<std::uint16_t>(derpRegion);
            const auto pong = disco->BuildPong(
                peer.DiscoPublicKey, message->Transaction, sourceAddress, sourcePort);
            if (source)
            {
                markDirect(peer, *source, "disco");
                SendUdp(peerSocket(peer), *source, pong);
            }
            else if (derpSource != nullptr)
            {
                if (sourceDerp != nullptr)
                {
                    sourceDerp->Send(*derpSource, pong, DerpWorker::Priority::Control);
                }
            }
            return;
        }
        if (message->Type == tailgate::disco::Disco::MessageType::Pong && source)
        {
            markDirect(peer, *source, "disco");
        }
        for (PendingPing& pending : pendingPings)
        {
            if (pending.Peer == &peer && !pending.Tsmp &&
                pending.Transaction == message->Transaction)
            {
                std::string endpoint;
                if (source)
                {
                    endpoint =
                        std::format("{}:{}", inet_ntoa(source->sin_addr), ntohs(source->sin_port));
                    (void)peer.Path.MarkDirect(ToMagicsockEndpoint(*source));
                }
                completePing(pending, true, endpoint, 0);
                break;
            }
        }
    };
    auto handleUdpWireGuard =
        [&](PeerRuntime& peer,
            std::optional<tailgate::wgengine::wireguard::WireGuardTunnel::ReceivedPacket> received,
            const sockaddr_in& source,
            int socketFd)
    {
        if (received && !received->Reply.empty())
        {
            SendUdp(socketFd, source, received->Reply);
        }
        if (received)
        {
            peer.Path.MarkDirectReceive();
        }
        std::vector<std::uint8_t> plain =
            received ? std::move(received->Plaintext) : std::vector<std::uint8_t>{};
        if (received && received->SessionEstablished)
        {
            tailgate::base::Log(tailgate::base::LogLevel::Debug,
                                "tunnel",
                                "session established peer=" + peer.Config.Name);
            markDirect(peer, source, "tunnel");
            flushPending(peer);
            return;
        }
        if (plain.empty())
        {
            return;
        }
        if (handleNodeControlPacket(peer, plain) || handlePingResponse(plain) ||
            handleDnsResponse(plain))
        {
            return;
        }
        markDirect(peer, source, "tunnel");
        queueTun(std::move(plain));
    };
    ControlUpdateWorker controlUpdates(control,
                                       controlFd,
                                       std::move(reconnectControl),
                                       configureHost ? &RelayHostControlFd : nullptr);
    UniqueFd epollFd(epoll_create1(EPOLL_CLOEXEC));
    if (epollFd.Fd < 0)
    {
        throw std::runtime_error("epoll_create1 failed: " + std::string(std::strerror(errno)));
    }
    UniqueFd maintenanceTimer = CreateTimerFd(DataplaneMaintenanceInterval);
    auto descriptorEvents = [](bool writable)
    {
        std::uint32_t events = EPOLLIN;
        if (writable)
        {
            events |= EPOLLOUT;
        }
        return events;
    };
    auto peerEvents = [](const PeerRuntime& peer)
    {
        std::uint32_t events = EPOLLIN;
        if (!peer.OutgoingPackets.empty())
        {
            events |= EPOLLOUT;
        }
        return events;
    };
    std::uint32_t currentTunEvents = descriptorEvents(!pendingTunPackets.empty());
    std::vector<std::uint32_t> currentPeerEvents;
    currentPeerEvents.reserve(peers.size());

    AddEpollInterest(
        epollFd.Fd, tun.Fd, currentTunEvents, PackDataplaneEvent(DataplaneEventKind::Tun));
    if (localDns.Fd >= 0)
    {
        AddEpollInterest(
            epollFd.Fd, localDns.Fd, EPOLLIN, PackDataplaneEvent(DataplaneEventKind::LocalDns));
    }
    for (std::size_t derpIndex = 0; derpIndex < derps.size(); ++derpIndex)
    {
        AddEpollInterest(
            epollFd.Fd,
            derps[derpIndex].Worker->NotifyFd(),
            EPOLLIN,
            PackDataplaneEvent(DataplaneEventKind::Derp, static_cast<std::uint32_t>(derpIndex)));
    }
    AddEpollInterest(
        epollFd.Fd, upstreamDns.Fd, EPOLLIN, PackDataplaneEvent(DataplaneEventKind::UpstreamDns));
    if (pingServer.Fd >= 0)
    {
        AddEpollInterest(
            epollFd.Fd, pingServer.Fd, EPOLLIN, PackDataplaneEvent(DataplaneEventKind::Ping));
    }
    AddEpollInterest(epollFd.Fd,
                     maintenanceTimer.Fd,
                     EPOLLIN,
                     PackDataplaneEvent(DataplaneEventKind::Maintenance));
    if (controlUpdates.Active())
    {
        AddEpollInterest(epollFd.Fd,
                         controlUpdates.Event.Fd,
                         EPOLLIN,
                         PackDataplaneEvent(DataplaneEventKind::Control));
    }
    if (networkMapFd >= 0)
    {
        AddEpollInterest(epollFd.Fd,
                         networkMapFd,
                         EPOLLIN,
                         PackDataplaneEvent(DataplaneEventKind::RelayControl));
    }
    AddEpollInterest(epollFd.Fd,
                     advertisedUdpFd,
                     EPOLLIN,
                     PackDataplaneEvent(DataplaneEventKind::AdvertisedUdp));
    for (std::size_t peerIndex = 0; peerIndex < peers.size(); ++peerIndex)
    {
        const std::uint32_t events = peerEvents(peers[peerIndex]);
        currentPeerEvents.push_back(events);
        AddEpollInterest(
            epollFd.Fd,
            peers[peerIndex].Socket.Fd,
            events,
            PackDataplaneEvent(DataplaneEventKind::Peer, static_cast<std::uint32_t>(peerIndex)));
    }

    auto updateEpollInterests = [&]()
    {
        const std::uint32_t desiredTunEvents = descriptorEvents(!pendingTunPackets.empty());
        if (desiredTunEvents != currentTunEvents)
        {
            ModifyEpollInterest(
                epollFd.Fd, tun.Fd, desiredTunEvents, PackDataplaneEvent(DataplaneEventKind::Tun));
            currentTunEvents = desiredTunEvents;
        }
        for (std::size_t peerIndex = 0; peerIndex < peers.size(); ++peerIndex)
        {
            const std::uint32_t desiredPeerEvents = peerEvents(peers[peerIndex]);
            if (desiredPeerEvents != currentPeerEvents[peerIndex])
            {
                ModifyEpollInterest(epollFd.Fd,
                                    peers[peerIndex].Socket.Fd,
                                    desiredPeerEvents,
                                    PackDataplaneEvent(DataplaneEventKind::Peer,
                                                       static_cast<std::uint32_t>(peerIndex)));
                currentPeerEvents[peerIndex] = desiredPeerEvents;
            }
        }
    };

    auto applyStatusFromNetworkMap = [&](const tailgate::types::netmap::NetworkConfig& config)
    {
        bool changed = false;
        for (const TailPeer& peer : config.Peers)
        {
            if (peer.Name.empty())
            {
                continue;
            }
            auto existing = std::find_if(status.Peers.begin(),
                                         status.Peers.end(),
                                         [&](const tailgate::linux_frontend::PeerStatus& peerStatus)
                                         {
                                             return peerStatus.Address == peer.Address;
                                         });
            if (existing == status.Peers.end())
            {
                tailgate::linux_frontend::PeerStatus added;
                added.Address = peer.Address;
                added.Hostname = DisplayName(peer.Name);
                added.OperatingSystem = peer.OperatingSystem;
                added.Relay = relayName(peer);
                added.Online = peer.Online;
                added.ExitNodeOption = peer.ExitNodeOption;
                status.Peers.push_back(std::move(added));
                changed = true;
                continue;
            }

            const bool shouldClearActivity = !peer.Online;
            changed = changed || existing->Hostname != DisplayName(peer.Name) ||
                      existing->OperatingSystem != peer.OperatingSystem ||
                      existing->Relay != relayName(peer) || existing->Online != peer.Online ||
                      existing->ExitNodeOption != peer.ExitNodeOption ||
                      (shouldClearActivity &&
                       (existing->Active || existing->Direct || !existing->Endpoint.empty() ||
                        existing->TxBytes != 0 || existing->RxBytes != 0));
            existing->Hostname = DisplayName(peer.Name);
            existing->OperatingSystem = peer.OperatingSystem;
            existing->Relay = relayName(peer);
            existing->Online = peer.Online;
            existing->ExitNodeOption = peer.ExitNodeOption;
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
            return std::any_of(config.Peers.begin(),
                               config.Peers.end(),
                               [&](const TailPeer& peer)
                               {
                                   return peer.Address == peerStatus.Address;
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
        TimedSection(
            "control DERP apply",
            [&]()
            {
                const std::size_t oldDerpCount = derps.size();
                (void)ensureDerpIndex(config.DerpRegion, config.DerpHost, false);
                for (const TailPeer& peer : config.Peers)
                {
                    if (peer.DerpRegion != 0 && !peer.DerpHost.empty())
                    {
                        (void)ensureDerpIndex(peer.DerpRegion, peer.DerpHost, false);
                    }
                }
                for (std::size_t derpIndex = oldDerpCount; derpIndex < derps.size(); ++derpIndex)
                {
                    AddEpollInterest(epollFd.Fd,
                                     derps[derpIndex].Worker->NotifyFd(),
                                     EPOLLIN,
                                     PackDataplaneEvent(DataplaneEventKind::Derp,
                                                        static_cast<std::uint32_t>(derpIndex)));
                }
            });

        TimedSection(
            "control peer apply",
            [&]()
            {
                for (const TailPeer& configPeer : config.Peers)
                {
                    auto existing =
                        std::find_if(peers.begin(),
                                     peers.end(),
                                     [&](const PeerRuntime& peer)
                                     {
                                         return (configPeer.NodeId != 0 &&
                                                 peer.Config.NodeId == configPeer.NodeId) ||
                                                peer.Config.Address == configPeer.Address;
                                     });
                    if (existing == peers.end())
                    {
                        std::optional<PeerRuntime> runtime = buildPeerRuntime(configPeer);
                        if (!runtime)
                        {
                            continue;
                        }
                        peers.push_back(std::move(*runtime));
                        const std::size_t peerIndex = peers.size() - 1;
                        const std::uint32_t events = peerEvents(peers[peerIndex]);
                        currentPeerEvents.push_back(events);
                        AddEpollInterest(epollFd.Fd,
                                         peers[peerIndex].Socket.Fd,
                                         events,
                                         PackDataplaneEvent(DataplaneEventKind::Peer,
                                                            static_cast<std::uint32_t>(peerIndex)));
                        tailgate::base::Log(
                            tailgate::base::LogLevel::Info,
                            "control",
                            std::format(
                                "added peer from network-map update: {} version={} ingress={} "
                                "wire-ingress={} peerapi4={} peerapi6={}",
                                configPeer.Name,
                                configPeer.ClientVersion,
                                configPeer.IngressEnabled ? 1 : 0,
                                configPeer.WireIngress ? 1 : 0,
                                configPeer.PeerApi4Port,
                                configPeer.PeerApi6Port));
                        continue;
                    }

                    if (existing->Config.Key != configPeer.Key)
                    {
                        tailgate::base::Log(
                            tailgate::base::LogLevel::Info,
                            "control",
                            std::format("peer key generation changed name={} address={} "
                                        "old-node={} new-node={}",
                                        configPeer.Name,
                                        configPeer.Address,
                                        existing->Config.NodeId,
                                        configPeer.NodeId));
                        const std::vector<std::uint8_t> publicKeyBytes =
                            tailgate::crypto::HexToBytes(configPeer.Key.substr(8));
                        if (publicKeyBytes.size() == existing->PublicKey.size())
                        {
                            std::copy(publicKeyBytes.begin(),
                                      publicKeyBytes.end(),
                                      existing->PublicKey.begin());
                            if (tunnel)
                            {
                                existing->TunnelPeer = tunnel->AddPeer(existing->PublicKey);
                            }
                            existing->Path.Reset(tailgate::wgengine::magicsock::PeerPathState::
                                                     ResetMode::ForgetVerifiedEndpoints);
                            existing->PendingPackets.clear();
                            existing->PendingBytes = 0;
                        }
                    }
                    const bool endpointsChanged =
                        existing->Config.Endpoints != configPeer.Endpoints;
                    const bool discoKeyChanged = existing->Config.DiscoKey != configPeer.DiscoKey;
                    const bool onlineChanged = existing->Config.Online != configPeer.Online;
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
                                        configPeer.Name,
                                        configPeer.Online ? 1 : 0,
                                        existing->HasDiscoKey ? 1 : 0,
                                        configPeer.Endpoints.size(),
                                        configPeer.ClientVersion,
                                        configPeer.IngressEnabled ? 1 : 0,
                                        configPeer.WireIngress ? 1 : 0,
                                        configPeer.PeerApi4Port,
                                        configPeer.PeerApi6Port));
                    }
                    if (!configPeer.Online || endpointsChanged)
                    {
                        existing->Path.Reset(!configPeer.Online || discoKeyChanged
                                                 ? tailgate::wgengine::magicsock::PeerPathState::
                                                       ResetMode::ForgetVerifiedEndpoints
                                                 : tailgate::wgengine::magicsock::PeerPathState::
                                                       ResetMode::PreserveVerifiedEndpoints);
                    }
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
                            const bool stillPresent =
                                std::any_of(config.Peers.begin(),
                                            config.Peers.end(),
                                            [&](const TailPeer& configPeer)
                                            {
                                                return (configPeer.NodeId != 0 &&
                                                        peer.Config.NodeId == configPeer.NodeId) ||
                                                       peer.Config.Address == configPeer.Address;
                                            });
                            if (!stillPresent)
                            {
                                if (!peer.Config.AllowedPrefixes.empty())
                                {
                                    tailgate::base::Log(
                                        tailgate::base::LogLevel::Info,
                                        "control",
                                        std::format("peer generation removed name={} address={} "
                                                    "node={}",
                                                    peer.Config.Name,
                                                    peer.Config.Address,
                                                    peer.Config.NodeId));
                                }
                                peer.Config.Online = false;
                                peer.Config.AllowedPrefixes.clear();
                                peer.Config.ExitNodeOption = false;
                                peer.Path.Reset(tailgate::wgengine::magicsock::PeerPathState::
                                                    ResetMode::ForgetVerifiedEndpoints);
                            }
                        }
                    });

                TimedSection(
                    "control DNS config apply",
                    [&]()
                    {
                        const bool resolverChanged = currentDnsResolver != config.DnsResolver;
                        const bool domainsChanged = currentDnsDomains != config.DnsDomains;
                        if (configureHost && resolverChanged)
                        {
                            currentDnsResolver = config.DnsResolver;
                            AddRoute(interfaceName,
                                     Ipv4Prefix{.Network = Ipv4ToHostOrder(currentDnsResolver),
                                                .PrefixLength = 32});
                        }
                        currentDnsDomains = config.DnsDomains;
                        currentDnsDefaultResolvers = config.DnsDefaultResolvers;
                        currentDnsRoutes = config.DnsRoutes;
                        if (configureHost && acceptDns && (resolverChanged || domainsChanged))
                        {
                            WriteResolver("127.0.0.1", currentDnsDomains);
                        }
                    });

                TimedSection("control route rebuild",
                             [&]()
                             {
                                 rebuildRoutablePeers();
                                 if (!exitNode.empty())
                                 {
                                     exitPeerIndex = tailgate::types::netmap::FindExitNode(
                                         routablePeers, exitNode, true);
                                     exitPeer = exitPeerIndex ? &peers[*exitPeerIndex] : nullptr;
                                 }
                                 dnsPeer = findRoute(Ipv4ToHostOrder(currentDnsResolver));
                             });
                TimedSection("control handshake refresh",
                             [&]()
                             {
                                 if (!tunnel)
                                 {
                                     return;
                                 }
                                 if (dnsPeer != nullptr)
                                 {
                                     sendHandshake(*dnsPeer);
                                 }
                                 if (exitPeer != nullptr && exitPeer != dnsPeer)
                                 {
                                     sendHandshake(*exitPeer);
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
            std::format("applied live network-map update: peers={}", config.Peers.size()));
        if (networkMapUpdated)
        {
            networkMapUpdated(config);
        }
    };

    std::vector<epoll_event> events(std::max<std::size_t>(16, peers.size() + derps.size() + 7));
    while (!StopRequested && !ReloadRequested)
    {
        updateEpollInterests();
        events.resize(std::max<std::size_t>(16, peers.size() + derps.size() + 7));
        const int result =
            epoll_wait(epollFd.Fd, events.data(), static_cast<int>(events.size()), -1);
        if (result < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            throw std::runtime_error("epoll_wait failed: " + std::string(std::strerror(errno)));
        }

        bool tunInput = false;
        bool tunOutput = false;
        bool localDnsInput = false;
        bool upstreamDnsInput = false;
        bool pingInput = false;
        bool controlInput = false;
        bool relayControlInput = false;
        bool advertisedUdpInput = false;
        bool maintenanceExpired = false;
        std::vector<std::uint32_t> readyDerps(derps.size(), 0);
        std::vector<std::uint32_t> readyPeers(peers.size(), 0);
        for (int eventIndex = 0; eventIndex < result; ++eventIndex)
        {
            const epoll_event& event = events[static_cast<std::size_t>(eventIndex)];
            const DataplaneEvent dataplaneEvent = UnpackDataplaneEvent(event.data.u64);
            if ((event.events & (EPOLLERR | EPOLLHUP)) != 0)
            {
                if (dataplaneEvent.Kind == DataplaneEventKind::Derp)
                {
                    throw std::runtime_error("DERP worker notification failed");
                }
                if (dataplaneEvent.Kind == DataplaneEventKind::Tun)
                {
                    throw std::runtime_error("TUN device closed");
                }
            }
            switch (dataplaneEvent.Kind)
            {
            case DataplaneEventKind::Tun:
                tunInput = tunInput || ((event.events & EPOLLIN) != 0);
                tunOutput = tunOutput || ((event.events & EPOLLOUT) != 0);
                break;
            case DataplaneEventKind::LocalDns:
                localDnsInput = localDnsInput || ((event.events & EPOLLIN) != 0);
                break;
            case DataplaneEventKind::Derp:
                if (dataplaneEvent.Index < readyDerps.size())
                {
                    readyDerps[dataplaneEvent.Index] |= event.events;
                }
                break;
            case DataplaneEventKind::UpstreamDns:
                upstreamDnsInput = upstreamDnsInput || ((event.events & EPOLLIN) != 0);
                break;
            case DataplaneEventKind::Ping:
                pingInput = pingInput || ((event.events & EPOLLIN) != 0);
                break;
            case DataplaneEventKind::Peer:
                if (dataplaneEvent.Index < readyPeers.size())
                {
                    readyPeers[dataplaneEvent.Index] |= event.events;
                }
                break;
            case DataplaneEventKind::AdvertisedUdp:
                advertisedUdpInput = advertisedUdpInput || ((event.events & EPOLLIN) != 0);
                break;
            case DataplaneEventKind::Maintenance:
                maintenanceExpired = maintenanceExpired || ((event.events & EPOLLIN) != 0);
                break;
            case DataplaneEventKind::Control:
                controlInput = controlInput || ((event.events & EPOLLIN) != 0);
                break;
            case DataplaneEventKind::RelayControl:
                relayControlInput = relayControlInput || ((event.events & EPOLLIN) != 0);
                break;
            }
        }

        if (controlInput && controlUpdates.Active())
        {
            std::uint64_t eventCount = 0;
            while (read(controlUpdates.Event.Fd, &eventCount, sizeof(eventCount)) ==
                   sizeof(eventCount))
            {
            }
            std::deque<tailgate::types::netmap::NetworkConfig> updates =
                controlUpdates.TakeUpdates();
            for (const tailgate::types::netmap::NetworkConfig& update : updates)
            {
                applyNetworkMap(update);
            }
        }
        if (relayControlInput && networkMapFd >= 0)
        {
            std::vector<std::uint8_t> payload(RelayNetworkMapBufferSize);
            const ssize_t received = recv(networkMapFd, payload.data(), payload.size(), 0);
            if (received <= 0)
            {
                throw std::runtime_error("relay network-map channel closed");
            }
            payload.resize(static_cast<std::size_t>(received));
            applyNetworkMap(tailgate::hosted::DecodeNetworkConfig(payload));
        }

        if (maintenanceExpired)
        {
            DrainTimerFd(maintenanceTimer.Fd);
        }
        if (tunOutput)
        {
            flushTun();
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
                        const std::string selectedResolver = selectDnsResolver(dnsPayload);
                        const std::uint32_t resolverAddress = Ipv4ToHostOrder(selectedResolver);
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
                                tailgate::net::packet::BuildUdpPacket(Ipv4ToHostOrder(selfIp),
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
                                 const std::string& target = request.Target;
                                 const std::string normalizedTarget =
                                     !target.empty() && target.back() == '.'
                                         ? target.substr(0, target.size() - 1)
                                         : target;
                                 const auto found = std::find_if(
                                     peers.begin(),
                                     peers.end(),
                                     [&](const PeerRuntime& peer)
                                     {
                                         std::string name = peer.Config.Name;
                                         if (!name.empty() && name.back() == '.')
                                         {
                                             name.pop_back();
                                         }
                                         const std::size_t dot = name.find('.');
                                         return peer.Config.Address == normalizedTarget ||
                                                name == normalizedTarget ||
                                                name.substr(0, dot) == normalizedTarget;
                                     });
                                 const bool tsmp = request.Tsmp;
                                 if (found == peers.end() || (!tsmp && !found->HasDiscoKey))
                                 {
                                     tailgate::base::Log(
                                         tailgate::base::LogLevel::Warning,
                                         "ping",
                                         found == peers.end()
                                             ? "target not found: " + normalizedTarget
                                             : std::format("target has no disco key: {} online={}",
                                                           found->Config.Name,
                                                           found->Config.Online ? 1 : 0));
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
                                         pending.Transaction = disco->NewTransactionId();
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

        if (tunInput)
        {
            TimedSection("TUN input", drainTunInput);
        }

        if (advertisedUdpInput)
        {
            TimedSection(
                "advertised UDP",
                [&]()
                {
                    for (std::size_t iteration = 0; iteration < MaximumPacketsPerDescriptorCycle;
                         ++iteration)
                    {
                        sockaddr_in source{};
                        std::vector<std::uint8_t> data = ReceiveUdp(advertisedUdpFd, &source);
                        if (data.empty())
                        {
                            break;
                        }
                        if (tailgate::disco::Disco::IsDiscoPacket(data))
                        {
                            if (data.size() < 38)
                            {
                                continue;
                            }
                            tailgate::crypto::Bytes32 sender{};
                            std::copy_n(data.begin() + 6, sender.size(), sender.begin());
                            PeerRuntime* peer = peerForDiscoKey(sender);
                            if (peer != nullptr)
                            {
                                peer->UseAdvertisedSocket = true;
                                peer->RxBytes += data.size();
                                if (encryptedPacketTransport)
                                {
                                    forwardEncryptedPacket(*peer, data, true, source);
                                }
                                else
                                {
                                    handleDisco(*peer, data, source, nullptr, nullptr);
                                }
                            }
                            continue;
                        }
                        if (encryptedPacketTransport)
                        {
                            const auto peer = std::find_if(peers.begin(),
                                                           peers.end(),
                                                           [&](const PeerRuntime& candidate)
                                                           {
                                                               return candidate.Path.IsVerified(
                                                                   ToMagicsockEndpoint(source));
                                                           });
                            if (peer != peers.end())
                            {
                                peer->UseAdvertisedSocket = true;
                                peer->RxBytes += data.size();
                                forwardEncryptedPacket(*peer, data, false, source);
                            }
                            continue;
                        }
                        auto received = tunnel->ProcessPacket(data);
                        if (!received)
                        {
                            continue;
                        }
                        auto peer = std::find_if(peers.begin(),
                                                 peers.end(),
                                                 [&](const PeerRuntime& candidate)
                                                 {
                                                     return candidate.TunnelPeer == received->Peer;
                                                 });
                        if (peer == peers.end())
                        {
                            continue;
                        }
                        peer->UseAdvertisedSocket = true;
                        peer->RxBytes += data.size();
                        handleUdpWireGuard(*peer, std::move(received), source, advertisedUdpFd);
                    }
                });
        }

        TimedSection(
            "peer UDP",
            [&]()
            {
                for (std::size_t peerIndex = 0; peerIndex < peers.size(); ++peerIndex)
                {
                    PeerRuntime& peer = peers[peerIndex];
                    if ((readyPeers[peerIndex] & EPOLLOUT) != 0)
                    {
                        flushOutgoing(peer);
                    }
                    if ((readyPeers[peerIndex] & EPOLLIN) == 0)
                    {
                        continue;
                    }
                    for (std::size_t iteration = 0; iteration < MaximumPacketsPerDescriptorCycle;
                         ++iteration)
                    {
                        sockaddr_in source{};
                        std::vector<std::uint8_t> data = ReceiveUdp(peer.Socket.Fd, &source);
                        if (data.empty())
                        {
                            break;
                        }
                        peer.RxBytes += data.size();
                        if (tailgate::disco::Disco::IsDiscoPacket(data))
                        {
                            if (encryptedPacketTransport)
                            {
                                forwardEncryptedPacket(peer, data, true, source);
                            }
                            else
                            {
                                handleDisco(peer, data, source, nullptr, nullptr);
                            }
                            continue;
                        }
                        if (encryptedPacketTransport)
                        {
                            forwardEncryptedPacket(peer, data, false, source);
                            continue;
                        }
                        handleUdpWireGuard(peer,
                                           tunnel->ProcessPacket(peer.TunnelPeer, data),
                                           source,
                                           peer.Socket.Fd);
                    }
                }
            });

        TimedSection(
            "DERP notify",
            [&]()
            {
                for (std::size_t derpIndex = 0; derpIndex < derps.size(); ++derpIndex)
                {
                    if ((readyDerps[derpIndex] & EPOLLIN) == 0)
                    {
                        continue;
                    }
                    DerpWorker& worker = *derps[derpIndex].Worker;
                    for (const tailgate::derp::DerpClient::Packet& packet : worker.ReceivePackets())
                    {
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
                                std::copy_n(
                                    packet.Payload.begin() + 6, sender.size(), sender.begin());
                                discoPeer = peerForDiscoKey(sender);
                            }
                            if (discoPeer != nullptr)
                            {
                                if (encryptedPacketTransport)
                                {
                                    forwardEncryptedPacket(
                                        *discoPeer, packet.Payload, true, std::nullopt);
                                }
                                else
                                {
                                    handleDisco(*discoPeer,
                                                packet.Payload,
                                                std::nullopt,
                                                &worker,
                                                &packet.Source);
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
                                            ? tailgate::crypto::BytesToHex(
                                                  packet.Payload.data() + 6, 8)
                                            : "<short>",
                                        peer->Config.Name));
                            }
                            continue;
                        }
                        if (encryptedPacketTransport)
                        {
                            forwardEncryptedPacket(*peer, packet.Payload, false, std::nullopt);
                            continue;
                        }
                        auto received = tunnel->ProcessPacket(peer->TunnelPeer, packet.Payload);
                        if (!received && packet.Payload.size() >= sizeof(std::uint32_t))
                        {
                            const std::uint32_t type =
                                static_cast<std::uint32_t>(packet.Payload[0]) |
                                (static_cast<std::uint32_t>(packet.Payload[1]) << 8U) |
                                (static_cast<std::uint32_t>(packet.Payload[2]) << 16U) |
                                (static_cast<std::uint32_t>(packet.Payload[3]) << 24U);
                            tailgate::base::Log(
                                tailgate::base::LogLevel::Debug,
                                "tunnel",
                                std::format("rejected DERP WireGuard packet peer={} "
                                            "type={} bytes={}",
                                            peer->Config.Name,
                                            type,
                                            packet.Payload.size()));
                        }
                        if (received && !received->Reply.empty())
                        {
                            worker.Send(
                                peer->PublicKey, received->Reply, DerpWorker::Priority::Control);
                        }
                        if (received && received->SessionEstablished)
                        {
                            tailgate::base::Log(tailgate::base::LogLevel::Debug,
                                                "tunnel",
                                                "session established peer=" + peer->Config.Name);
                            flushPending(*peer);
                        }
                        if (received && !received->Plaintext.empty())
                        {
                            if (handleNodeControlPacket(*peer, received->Plaintext) ||
                                handlePingResponse(received->Plaintext))
                            {
                                continue;
                            }
                            if (!handleDnsResponse(received->Plaintext))
                            {
                                queueTun(std::move(received->Plaintext));
                            }
                        }
                    }
                }
            });

        if (maintenanceExpired)
        {
            TimedSection("timers",
                         [&]()
                         {
                             for (PeerRuntime& peer : peers)
                             {
                                 if (peer.Path.ExpireDirectPath(std::chrono::steady_clock::now()))
                                 {
                                     tailgate::base::Log(tailgate::base::LogLevel::Info,
                                                         "tunnel",
                                                         "relay fallback peer=" + peer.Config.Name);
                                     for (auto& peerStatus : status.Peers)
                                     {
                                         if (peerStatus.Address == peer.Config.Address)
                                         {
                                             peerStatus.Direct = false;
                                             peerStatus.Endpoint.clear();
                                         }
                                     }
                                     submitStatus(status);
                                 }
                                 if (!tunnel)
                                 {
                                     continue;
                                 }
                                 if (tunnel->HasSession(peer.TunnelPeer) &&
                                     !peer.Path.HasDirectPath())
                                 {
                                     startDirectProbe(peer);
                                 }
                                 auto action = tunnel->UpdateTimers(peer.TunnelPeer);
                                 if (action == tailgate::wgengine::wireguard::WireGuardTunnel::
                                                   TimerAction::SendHandshake)
                                 {
                                     sendHandshake(peer);
                                 }
                                 else if (action == tailgate::wgengine::wireguard::WireGuardTunnel::
                                                        TimerAction::SendKeepalive)
                                 {
                                     sendPeer(peer, tunnel->Encrypt(peer.TunnelPeer, {}), false);
                                 }
                                 for (auto& peerStatus : status.Peers)
                                 {
                                     if (peerStatus.Address == peer.Config.Address)
                                     {
                                         peerStatus.Active = tunnel->HasSession(peer.TunnelPeer);
                                         peerStatus.TxBytes = peer.TxBytes;
                                         peerStatus.RxBytes = peer.RxBytes;
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
                                            pending.Peer->Config.Name,
                                            pending.Peer->Config.Online ? 1 : 0,
                                            pending.Peer->HasDiscoKey ? 1 : 0,
                                            pending.Peer->Config.Endpoints.size()));
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

void RunHostedRelay(tailgate::base::IByteStream& stream,
                    const std::string& expectedDomain,
                    const std::string& relayHostName,
                    const std::string& relayHostAddress,
                    const tailgate::crypto::Bytes32& relayPrivateKey,
                    const tailgate::crypto::Bytes32& relayPublicKey,
                    const std::function<void()>& closeConnection,
                    const std::function<void()>& markIdentityVerified);

void UpdateRelayHostNetworkMap(const tailgate::types::netmap::NetworkConfig& config);
[[nodiscard]] bool WaitForHostedNodeVisibility(const std::string& tailnet,
                                               std::uint64_t nodeId,
                                               const tailgate::crypto::Bytes32& nodePublicKey);

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

void WaitForTlsIo(int fd, bool needsRead)
{
    constexpr int DnsIoTimeoutMilliseconds = 15000;
    pollfd descriptor{};
    descriptor.fd = fd;
    descriptor.events = needsRead ? POLLIN : POLLOUT;
    int result = 0;
    do
    {
        result = poll(&descriptor, 1, DnsIoTimeoutMilliseconds);
    } while (result < 0 && errno == EINTR);
    if (result == 0)
    {
        throw std::runtime_error("DNS-over-TLS operation timed out");
    }
    if (result < 0 || (descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
    {
        throw std::runtime_error("DNS-over-TLS transport failed");
    }
}

void WriteTlsBlocking(tailgate::net::tls::TlsStream& tls,
                      int fd,
                      const std::vector<std::uint8_t>& data)
{
    std::size_t offset = 0;
    while (offset < data.size())
    {
        const std::optional<std::size_t> written =
            tls.TryWriteSome(data.data() + offset, data.size() - offset);
        if (!written)
        {
            WaitForTlsIo(fd, tls.WriteNeedsRead());
            continue;
        }
        if (*written == 0)
        {
            throw std::runtime_error("DNS-over-TLS stream closed during write");
        }
        offset += *written;
    }
}

std::vector<std::uint8_t>
ReadTlsBlocking(tailgate::net::tls::TlsStream& tls, int fd, std::size_t size)
{
    std::vector<std::uint8_t> result;
    result.reserve(size);
    while (result.size() < size)
    {
        std::optional<std::vector<std::uint8_t>> part = tls.TryReadSome(size - result.size());
        if (!part)
        {
            WaitForTlsIo(fd, !tls.ReadNeedsWrite());
            continue;
        }
        if (part->empty())
        {
            throw std::runtime_error("DNS-over-TLS stream closed during read");
        }
        result.insert(result.end(), part->begin(), part->end());
    }
    return result;
}

RelayEndpoint ResolveRelayEndpoint(RelayEndpoint endpoint,
                                   const std::string& interfaceName,
                                   std::size_t addressAttempt)
{
    constexpr const char* CloudflareAddress = "1.1.1.1";
    constexpr const char* CloudflareTlsName = "cloudflare-dns.com";
    constexpr const char* DnsOverTlsPort = "853";
    constexpr std::size_t MaximumCanonicalQueries = 8;
    if (tailgate::net::packet::ParseIpv4(endpoint.Host))
    {
        endpoint.ConnectAddress = endpoint.Host;
        return endpoint;
    }
    tailgate::linux_frontend::TcpStream dnsTransport(
        CloudflareAddress, DnsOverTlsPort, interfaceName);
    tailgate::net::tls::TlsStream dnsTls(
        dnsTransport, CloudflareTlsName, tailgate::linux_frontend::SystemCaBundle(), true);
    const auto queryDns = [&dnsTls, &dnsTransport](const std::string& current)
    {
        const tailgate::crypto::Bytes32 random = tailgate::crypto::GeneratePrivateKey();
        const std::uint16_t transaction = (static_cast<std::uint16_t>(random[0]) << 8U) | random[1];
        std::vector<std::uint8_t> query = tailgate::net::dns::BuildDnsQuery(current, transaction);
        if (query.size() > 65535)
        {
            throw std::runtime_error("DNS-over-TLS query is too large");
        }
        query.insert(query.begin(),
                     {static_cast<std::uint8_t>(query.size() >> 8U),
                      static_cast<std::uint8_t>(query.size())});
        WriteTlsBlocking(dnsTls, dnsTransport.NativeHandle(), query);
        const std::vector<std::uint8_t> lengthBytes =
            ReadTlsBlocking(dnsTls, dnsTransport.NativeHandle(), 2);
        const std::size_t responseLength =
            (static_cast<std::size_t>(lengthBytes[0]) << 8U) | lengthBytes[1];
        return tailgate::net::dns::ParseDnsAnswer(
            ReadTlsBlocking(dnsTls, dnsTransport.NativeHandle(), responseLength),
            transaction,
            current);
    };
    const tailgate::net::dns::DnsTarget target = tailgate::net::dns::ResolveDnsTarget(
        endpoint.Host, queryDns, addressAttempt, MaximumCanonicalQueries);
    endpoint.Host = target.ValidationName;
    endpoint.ConnectAddress = target.ConnectAddress;
    tailgate::base::Log(
        tailgate::base::LogLevel::Info,
        "dns",
        std::format("relay resolution name={} address={}", endpoint.Host, endpoint.ConnectAddress));
    return endpoint;
}

tailgate::control::client::RegistrationOptions BuildRegistrationOptions(
    const std::string& followupUrl,
    const std::string& reauthorizationKey,
    const std::function<void(const tailgate::control::client::RegistrationResult&)>&
        registrationPending)
{
    tailgate::control::client::RegistrationOptions result;
    result.InitialFollowupUrl = followupUrl;
    result.ReauthorizationKey = reauthorizationKey;
    if (registrationPending)
    {
        result.StateChanged = registrationPending;
    }
    else
    {
        result.StateChanged = [](const tailgate::control::client::RegistrationResult&)
        {
            throw std::runtime_error("registration requires user action");
        };
    }
    result.WaitForRetry = [](std::chrono::milliseconds delay)
    {
        constexpr std::chrono::milliseconds RetryWaitSlice{100};
        std::chrono::milliseconds waited{0};
        while (waited < delay && !StopRequested && !ReloadRequested)
        {
            const std::chrono::milliseconds slice = std::min(RetryWaitSlice, delay - waited);
            std::this_thread::sleep_for(slice);
            waited += slice;
        }
        return !StopRequested && !ReloadRequested;
    };
    return result;
}

void RunRelayConnection(
    const std::string& url,
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
    const std::function<void()>& registrationAccepted,
    const std::function<void(const tailgate::control::client::RegistrationResult&)>&
        registrationPending,
    const std::string& reauthorizationKey)
{
    const std::string underlayInterface = DefaultRouteInterface();
    const RelayEndpoint endpoint =
        ResolveRelayEndpoint(ParseRelayEndpoint(url), underlayInterface, addressAttempt);
    const std::vector<std::string> originalResolvers = ReadResolverAddresses();
    std::unique_ptr<tailgate::control::client::ControlClient> dialedControl;
    tailgate::linux_frontend::DialedControlStream controlStream =
        tailgate::linux_frontend::DialControl(
            underlayInterface,
            [&](tailgate::base::IByteStream& stream)
            {
                dialedControl = std::make_unique<tailgate::control::client::ControlClient>(
                    stream, machinePrivateKey, nodePrivateKey, host);
            });
    tailgate::control::client::ControlClient& control = *dialedControl;
    control.SetDiscoPrivateKey(discoPrivateKey);
    const tailgate::control::client::RegistrationOptions registrationOptions =
        BuildRegistrationOptions(followupUrl, reauthorizationKey, registrationPending);
    tailgate::control::client::RegistrationResult registration =
        control.RegisterUntilAuthorized(authKey, registrationOptions);
    if (!registration.Network)
    {
        throw std::runtime_error("control registration completed without a network map");
    }
    tailgate::types::netmap::NetworkConfig config = std::move(*registration.Network);
    registrationAccepted();
    control.UpdateHostInfo(config.DerpRegion);
    if (!registration.NetworkMapStreaming)
    {
        control.SetPreferredDerp(config.DerpRegion);
    }

    tailgate::linux_frontend::TcpStream transport(
        endpoint.ConnectAddress,
        endpoint.Port,
        underlayInterface,
        tailgate::linux_frontend::TcpStream::ControlIoTimeoutSeconds);
    tailgate::net::tls::TlsStream tls(
        transport, endpoint.Host, tailgate::linux_frontend::SystemCaBundle(), true);
    tailgate::hosted::Decoder decoder;
    decoder.Feed(tailgate::hosted::RequestHttpUpgrade(
        tls, std::format("{}:{}", endpoint.Host, endpoint.Port)));
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
    const tailgate::hosted::Frame challengeFrame = tailgate::hosted::ReadFrame(tls, decoder);
    if (challengeFrame.Type != tailgate::hosted::MessageType::ServerChallenge)
    {
        throw std::runtime_error("tailgate server did not provide an identity challenge");
    }
    const tailgate::hosted::Challenge challenge =
        tailgate::hosted::DecodeChallenge(challengeFrame.Payload);
    if (savedSession && savedSession->ServerUrl == url && hasKey(savedSession->RelayPublicKey) &&
        savedSession->RelayPublicKey != challenge.RelayPublicKey)
    {
        // The HTTPS certificate authenticates the server, so a rotated relay node key (for
        // example after the relay recreated its identity) is only worth a notice.
        tailgate::base::Log(tailgate::base::LogLevel::Info,
                            "relay",
                            "tailgate server node key changed; trusting the TLS certificate");
    }

    tailgate::hosted::Authentication request;
    request.Tailnet = config.Domain;
    request.NodeId = config.SelfNodeId;
    request.Hostname = host.Hostname;
    request.OperatingSystem = host.OperatingSystem;
    request.OperatingSystemVersion = host.OperatingSystemVersion;
    request.NodePublicKey = control.NodePublicKey();
    request.ClientNonce = tailgate::crypto::GeneratePrivateKey();
    request.ClientProof = tailgate::hosted::CreateClientProof(
        nodePrivateKey, challenge.RelayPublicKey, challenge.ServerNonce, request.ClientNonce);
    tailgate::hosted::WriteFrame(
        tls,
        tailgate::hosted::Frame{.Type = tailgate::hosted::MessageType::Authenticate,
                                .Payload = tailgate::hosted::EncodeAuthentication(request)});
    const tailgate::hosted::Frame authentication = tailgate::hosted::ReadFrame(tls, decoder);
    if (authentication.Type == tailgate::hosted::MessageType::Rejected)
    {
        throw std::runtime_error("tailgate server rejected authentication: " +
                                 tailgate::hosted::DecodeRejection(authentication.Payload).Reason);
    }
    if (authentication.Type != tailgate::hosted::MessageType::Authenticated)
    {
        throw std::runtime_error("tailgate server returned an invalid authentication response");
    }
    const tailgate::hosted::Session session =
        tailgate::hosted::DecodeSession(authentication.Payload);
    const tailgate::crypto::Bytes32 expectedServerProof = tailgate::hosted::CreateServerProof(
        nodePrivateKey, challenge.RelayPublicKey, challenge.ServerNonce, request.ClientNonce);
    if (!tailgate::hosted::ProofMatches(expectedServerProof, session.ServerProof))
    {
        throw std::runtime_error("tailgate server identity proof is invalid");
    }
    std::string relayHostName = session.RelayHostName;
    tailgate::linux_frontend::WriteRelaySession(tailgate::linux_frontend::RelaySessionState{
        .ServerUrl = url, .Tailnet = session.Tailnet, .RelayPublicKey = challenge.RelayPublicKey});
    if (config.Domain != session.Tailnet)
    {
        throw std::runtime_error("tailgate session and network map tailnets differ");
    }
    bool relayHostStateKnown = false;
    bool relayHostOnline = false;
    const auto updateRelayHostState = [&](const tailgate::types::netmap::NetworkConfig& next)
    {
        const auto relayHost = std::find_if(next.Peers.begin(),
                                            next.Peers.end(),
                                            [&](const TailPeer& peer)
                                            {
                                                return peer.Address == session.RelayHostAddress;
                                            });
        const bool online = relayHost != next.Peers.end() && relayHost->Online;
        if (relayHost != next.Peers.end())
        {
            relayHostName = DisplayName(relayHost->Name);
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
    std::string effectiveExitNode = exitNode;
    if (!effectiveExitNode.empty() &&
        !tailgate::types::netmap::FindExitNode(config.Peers, effectiveExitNode, true))
    {
        tailgate::base::Log(tailgate::base::LogLevel::Warning,
                            "control",
                            "exit node not found or offline; continuing without it: " +
                                effectiveExitNode);
        effectiveExitNode.clear();
    }
    tailgate::hosted::WriteFrame(
        tls,
        tailgate::hosted::Frame{.Type = tailgate::hosted::MessageType::NetworkMap,
                                .Payload = tailgate::hosted::EncodeNetworkConfig(config)});
    tailgate::wgengine::wireguard::WireGuardRouter router(
        nodePrivateKey, config.Peers, effectiveExitNode);
    tailgate::disco::Disco disco(discoPrivateKey, request.NodePublicKey);

    const std::string interfaceName = "tailgate0";
    constexpr Ipv4Prefix LowerDefaultRoute{.Network = 0, .PrefixLength = 1};
    constexpr Ipv4Prefix UpperDefaultRoute{.Network = 0x80000000U, .PrefixLength = 1};
    UniqueFd tun = OpenTun(interfaceName);
    SetInterfaceAddress(interfaceName, config.SelfAddress);
    const std::string selfIpv6 = FirstIpv6Address(config.SelfAddresses);
    if (!selfIpv6.empty())
    {
        SetInterfaceIpv6Address(interfaceName, selfIpv6);
    }
    SetInterfaceMtu(interfaceName, TailgateMtu);
    AddRoute(interfaceName,
             Ipv4Prefix{.Network = Ipv4ToHostOrder("100.64.0.0"), .PrefixLength = 10});
    if (!effectiveExitNode.empty())
    {
        AddRoute(interfaceName, LowerDefaultRoute);
        AddRoute(interfaceName, UpperDefaultRoute);
    }
    if (!config.DnsResolver.empty())
    {
        AddRoute(interfaceName,
                 Ipv4Prefix{.Network = Ipv4ToHostOrder(config.DnsResolver), .PrefixLength = 32});
    }
    if (acceptDns && !config.DnsResolver.empty())
    {
        WriteResolver("127.0.0.1", config.DnsDomains);
    }

    const auto applyNetworkMap = [&](const tailgate::types::netmap::NetworkConfig& next)
    {
        if (next.Domain != session.Tailnet || next.SelfAddress != config.SelfAddress)
        {
            throw std::runtime_error("tailgate relay changed the client identity");
        }
        config = next;
        const bool wasExitNodeEnabled = !effectiveExitNode.empty();
        const bool exitNodeAvailable = !exitNode.empty() && tailgate::types::netmap::FindExitNode(
                                                                config.Peers, exitNode, true);
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
        if (wasExitNodeEnabled != !effectiveExitNode.empty())
        {
            const auto updateRoute = effectiveExitNode.empty() ? RemoveRoute : AddRoute;
            updateRoute(interfaceName, LowerDefaultRoute);
            updateRoute(interfaceName, UpperDefaultRoute);
        }
        router.UpdatePeers(config.Peers, effectiveExitNode);
        updateRelayHostState(config);
        status.BackendState = "Running";
        status.Online = true;
        status.Address = config.SelfAddress;
        status.Domain = config.Domain;
        status.Hostname = DisplayName(config.SelfName);
        status.Error.clear();
        status.Peers.clear();
        for (const TailPeer& peer : config.Peers)
        {
            if (peer.Name.empty())
            {
                continue;
            }
            tailgate::linux_frontend::PeerStatus peerStatus;
            peerStatus.Address = peer.Address;
            peerStatus.Hostname = DisplayName(peer.Name);
            peerStatus.OperatingSystem = peer.OperatingSystem;
            peerStatus.Relay = peer.DerpCode;
            peerStatus.Online = peer.Online;
            peerStatus.ExitNodeOption = peer.ExitNodeOption;
            status.Peers.push_back(std::move(peerStatus));
        }
        if (acceptDns && !config.DnsResolver.empty())
        {
            WriteResolver("127.0.0.1", config.DnsDomains);
        }
        tailgate::linux_frontend::WriteDaemonStatus(status);
    };
    applyNetworkMap(config);
    transport.SetNonBlocking(true);
    controlStream.Stream->SetNonBlocking(true);
    const int epoll = epoll_create1(EPOLL_CLOEXEC);
    if (epoll < 0)
    {
        throw std::runtime_error("relay epoll_create1 failed");
    }
    UniqueFd epollFd(epoll);
    UniqueFd pingServer = tailgate::linux_frontend::OpenPingServer();
    UniqueFd localDns = acceptDns ? OpenLocalDnsSocket() : UniqueFd{};
    UniqueFd upstreamDns = OpenUdpSocket(underlayInterface);
    UniqueFd maintenanceTimer = CreateTimerFd(std::chrono::milliseconds(250));
    AddEpollInterest(epollFd.Fd, tun.Fd, EPOLLIN, PackDataplaneEvent(DataplaneEventKind::Tun));
    AddEpollInterest(epollFd.Fd,
                     transport.NativeHandle(),
                     EPOLLIN,
                     PackDataplaneEvent(DataplaneEventKind::Control));
    AddEpollInterest(epollFd.Fd,
                     controlStream.Stream->NativeHandle(),
                     EPOLLIN,
                     PackDataplaneEvent(DataplaneEventKind::RelayControl));
    AddEpollInterest(
        epollFd.Fd, pingServer.Fd, EPOLLIN, PackDataplaneEvent(DataplaneEventKind::Ping));
    if (localDns.Fd >= 0)
    {
        AddEpollInterest(
            epollFd.Fd, localDns.Fd, EPOLLIN, PackDataplaneEvent(DataplaneEventKind::LocalDns));
    }
    AddEpollInterest(
        epollFd.Fd, upstreamDns.Fd, EPOLLIN, PackDataplaneEvent(DataplaneEventKind::UpstreamDns));
    AddEpollInterest(epollFd.Fd,
                     maintenanceTimer.Fd,
                     EPOLLIN,
                     PackDataplaneEvent(DataplaneEventKind::Maintenance));
    if (readyFd >= 0)
    {
        const char ready = '1';
        (void)write(readyFd, &ready, 1);
        close(readyFd);
        readyFd = -1;
    }
    std::deque<std::vector<std::uint8_t>> socketOutput;
    std::size_t socketOffset = 0;
    std::size_t socketOutputBytes = 0;
    std::deque<std::vector<std::uint8_t>> tunOutput;
    std::size_t tunOutputBytes = 0;

    struct PendingRelayPing
    {
        tailgate::net::packet::TsmpToken TsmpToken{};
        tailgate::disco::Disco::TransactionId DiscoTransaction{};
        tailgate::crypto::Bytes32 Peer{};
        sockaddr_un Client{};
        socklen_t ClientLength = 0;
        std::chrono::steady_clock::time_point Started{};
        int TimeoutSeconds = 0;
        std::string Name;
        std::string Address;
        std::string Relay;
        bool Tsmp = false;
    };

    std::vector<PendingRelayPing> pendingPings;
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
    const auto selectDnsResolver = [&](const std::vector<std::uint8_t>& query)
    {
        const std::optional<std::string> name = tailgate::net::dns::DnsQueryName(query);
        const std::vector<std::string>* selected = nullptr;
        std::size_t selectedSuffixLength = 0;
        for (const tailgate::types::netmap::NetworkConfig::DnsRoute& route : config.DnsRoutes)
        {
            if (name && route.Suffix.size() >= selectedSuffixLength &&
                tailgate::net::dns::DnsNameHasSuffix(*name, route.Suffix))
            {
                selected = &route.Resolvers;
                selectedSuffixLength = route.Suffix.size();
            }
        }
        if (selected != nullptr)
        {
            const std::string resolver = selected->empty() ? config.DnsResolver : selected->front();
            return std::pair<std::string, bool>{resolver, true};
        }
        if (originalResolvers.empty())
        {
            throw std::runtime_error("no underlay DNS resolver is available");
        }
        return std::pair<std::string, bool>{originalResolvers.front(), false};
    };
    const auto updateSocketEvents = [&]()
    {
        epoll_event event{};
        event.events = EPOLLIN | (socketOutput.empty() && !tls.ReadNeedsWrite() ? 0U : EPOLLOUT);
        event.data.u64 = PackDataplaneEvent(DataplaneEventKind::Control);
        if (epoll_ctl(epollFd.Fd, EPOLL_CTL_MOD, transport.NativeHandle(), &event) != 0)
        {
            throw std::runtime_error("relay socket epoll update failed");
        }
    };
    const auto updateTunEvents = [&]()
    {
        epoll_event event{};
        event.events = EPOLLIN | (tunOutput.empty() ? 0U : EPOLLOUT);
        event.data.u64 = PackDataplaneEvent(DataplaneEventKind::Tun);
        if (epoll_ctl(epollFd.Fd, EPOLL_CTL_MOD, tun.Fd, &event) != 0)
        {
            throw std::runtime_error("relay TUN epoll update failed");
        }
    };
    const auto queueFrame = [&](tailgate::hosted::Frame frame)
    {
        std::vector<std::uint8_t> encoded = tailgate::hosted::Encode(frame);
        socketOutputBytes += encoded.size();
        if (socketOutputBytes > MaximumPendingBytesPerPeer)
        {
            throw std::runtime_error("relay socket output queue limit exceeded");
        }
        socketOutput.push_back(std::move(encoded));
        updateSocketEvents();
    };
    const auto queueTransportPackets =
        [&](std::vector<tailgate::wgengine::wireguard::WireGuardRouter::TransportPacket> packets)
    {
        for (tailgate::wgengine::wireguard::WireGuardRouter::TransportPacket& packet : packets)
        {
            queueFrame(tailgate::hosted::Frame{
                .Type = tailgate::hosted::MessageType::ClientPacket,
                .Payload = tailgate::hosted::EncodePeerPacket(tailgate::hosted::PeerPacket{
                    .Peer = packet.Peer, .Payload = packet.Payload, .Control = packet.Control})});
        }
    };
    const auto peerDiscoKey =
        [&](const tailgate::crypto::Bytes32& nodeKey) -> std::optional<tailgate::crypto::Bytes32>
    {
        const std::string encodedNodeKey =
            "nodekey:" + tailgate::crypto::BytesToHex(nodeKey.data(), nodeKey.size());
        const auto peer = std::find_if(config.Peers.begin(),
                                       config.Peers.end(),
                                       [&](const TailPeer& candidate)
                                       {
                                           return candidate.Key == encodedNodeKey &&
                                                  candidate.DiscoKey.rfind("discokey:", 0) == 0;
                                       });
        if (peer == config.Peers.end())
        {
            return std::nullopt;
        }
        const std::vector<std::uint8_t> bytes =
            tailgate::crypto::HexToBytes(peer->DiscoKey.substr(9));
        if (bytes.size() != tailgate::crypto::Bytes32{}.size())
        {
            return std::nullopt;
        }
        tailgate::crypto::Bytes32 result{};
        std::copy(bytes.begin(), bytes.end(), result.begin());
        return result;
    };
    const auto queueDisco = [&](const tailgate::crypto::Bytes32& peer,
                                std::vector<std::uint8_t> payload,
                                std::uint32_t address = 0,
                                std::uint16_t port = 0)
    {
        queueFrame(
            tailgate::hosted::Frame{.Type = tailgate::hosted::MessageType::ClientPacket,
                                    .Payload = tailgate::hosted::EncodePeerPacket(
                                        tailgate::hosted::PeerPacket{.Peer = peer,
                                                                     .Payload = std::move(payload),
                                                                     .Disco = true,
                                                                     .EndpointAddress = address,
                                                                     .EndpointPort = port})});
    };
    const auto completePing =
        [&](PendingRelayPing& pending, bool responded, std::uint16_t peerApiPort)
    {
        tailgate::linux_frontend::PingResponse response{};
        response.Responded = responded;
        response.LatencyMilliseconds =
            static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - pending.Started)
                                 .count());
        response.NodeName = pending.Name;
        response.NodeAddress = pending.Address;
        response.Relay = pending.Relay;
        response.Endpoint = std::format("tailgate({})", relayHostName);
        response.PeerApiPort = peerApiPort;
        tailgate::linux_frontend::SendPingResponse(
            pingServer.Fd, pending.Client, pending.ClientLength, response);
        pending.ClientLength = 0;
    };
    const auto handleDisco = [&](const tailgate::hosted::PeerPacket& packet)
    {
        const std::optional<tailgate::crypto::Bytes32> expectedSender = peerDiscoKey(packet.Peer);
        const std::optional<tailgate::disco::Disco::Message> message = disco.Parse(packet.Payload);
        if (!expectedSender || !message || message->Sender != *expectedSender)
        {
            tailgate::base::Log(tailgate::base::LogLevel::Warning,
                                "relay",
                                "dropping unauthenticated relayed disco packet");
            return;
        }
        if (message->Type == tailgate::disco::Disco::MessageType::Ping)
        {
            queueDisco(packet.Peer,
                       disco.BuildPong(*expectedSender,
                                       message->Transaction,
                                       packet.EndpointAddress,
                                       packet.EndpointPort),
                       packet.EndpointAddress,
                       packet.EndpointPort);
        }
        else if (message->Type == tailgate::disco::Disco::MessageType::CallMeMaybe)
        {
            const tailgate::disco::Disco::TransactionId transaction = disco.NewTransactionId();
            const std::vector<std::uint8_t> ping = disco.BuildPing(*expectedSender, transaction);
            for (const tailgate::disco::Disco::Endpoint& endpoint : message->Endpoints)
            {
                queueDisco(packet.Peer, ping, endpoint.Address, endpoint.Port);
            }
        }
        else if (message->Type == tailgate::disco::Disco::MessageType::Pong)
        {
            const auto pending =
                std::find_if(pendingPings.begin(),
                             pendingPings.end(),
                             [&](const PendingRelayPing& candidate)
                             {
                                 return candidate.ClientLength != 0 && !candidate.Tsmp &&
                                        candidate.Peer == packet.Peer &&
                                        candidate.DiscoTransaction == message->Transaction;
                             });
            if (pending != pendingPings.end())
            {
                completePing(*pending, true, 0);
            }
        }
    };
    const auto handlePlaintext = [&](std::vector<std::uint8_t> packet)
    {
        const auto dns = std::find_if(
            pendingDns.begin(),
            pendingDns.end(),
            [&](const PendingRelayDns& pending)
            {
                const auto payload =
                    tailgate::net::packet::ExtractUdpPayload(packet,
                                                             pending.Resolver,
                                                             Ipv4ToHostOrder(config.SelfAddress),
                                                             53,
                                                             pending.SourcePort);
                return payload && payload->size() >= 2 &&
                       (((static_cast<std::uint16_t>((*payload)[0]) << 8U) | (*payload)[1]) ==
                        pending.Id);
            });
        if (dns != pendingDns.end())
        {
            const auto payload = tailgate::net::packet::ExtractUdpPayload(
                packet, dns->Resolver, Ipv4ToHostOrder(config.SelfAddress), 53, dns->SourcePort);
            SendUdp(localDns.Fd, dns->Client, *payload);
            pendingDns.erase(dns);
            return;
        }
        if (const auto pong = tailgate::net::packet::BuildTsmpPong(packet, 0))
        {
            queueTransportPackets(router.Send(*pong));
            return;
        }
        if (const auto pong = tailgate::net::packet::ParseTsmpPong(packet))
        {
            const auto pending = std::find_if(pendingPings.begin(),
                                              pendingPings.end(),
                                              [&](const PendingRelayPing& candidate)
                                              {
                                                  return candidate.ClientLength != 0 &&
                                                         candidate.Tsmp &&
                                                         candidate.TsmpToken == pong->Token;
                                              });
            if (pending != pendingPings.end())
            {
                completePing(*pending, true, pong->PeerApiPort);
            }
            return;
        }
        tunOutputBytes += packet.size();
        if (tunOutputBytes > MaximumPendingBytesPerPeer)
        {
            throw std::runtime_error("relay TUN output queue limit exceeded");
        }
        tunOutput.push_back(std::move(packet));
        updateTunEvents();
    };
    while (!StopRequested && !ReloadRequested)
    {
        std::array<epoll_event, 8> events{};
        const int count = epoll_wait(epollFd.Fd, events.data(), events.size(), -1);
        if (count < 0 && errno == EINTR)
        {
            continue;
        }
        if (count < 0)
        {
            throw std::runtime_error("relay epoll_wait failed");
        }
        for (int index = 0; index < count; ++index)
        {
            const DataplaneEvent event = UnpackDataplaneEvent(events[index].data.u64);
            if ((events[index].events & (EPOLLERR | EPOLLHUP)) != 0)
            {
                throw std::runtime_error(event.Kind == DataplaneEventKind::RelayControl
                                             ? "tailnet control stream closed"
                                             : "tailgate relay transport closed");
            }
            if (event.Kind == DataplaneEventKind::RelayControl &&
                (events[index].events & EPOLLIN) != 0)
            {
                while (std::optional<tailgate::types::netmap::NetworkConfig> update =
                           control.PollNetworkMap())
                {
                    applyNetworkMap(*update);
                    queueFrame(tailgate::hosted::Frame{
                        .Type = tailgate::hosted::MessageType::NetworkMap,
                        .Payload = tailgate::hosted::EncodeNetworkConfig(*update)});
                }
            }
            if (event.Kind == DataplaneEventKind::Tun && (events[index].events & EPOLLIN) != 0)
            {
                std::vector<std::uint8_t> packet(RelayPacketBufferSize);
                const ssize_t size = read(tun.Fd, packet.data(), packet.size());
                if (size > 0)
                {
                    packet.resize(static_cast<std::size_t>(size));
                    queueTransportPackets(router.Send(packet));
                }
            }
            if (event.Kind == DataplaneEventKind::Ping && (events[index].events & EPOLLIN) != 0)
            {
                tailgate::linux_frontend::PingRequest pingRequest{};
                sockaddr_un client{};
                socklen_t clientLength = sizeof(client);
                if (tailgate::linux_frontend::ReceivePingRequest(
                        pingServer.Fd, pingRequest, client, clientLength))
                {
                    std::string target = pingRequest.Target;
                    if (!target.empty() && target.back() == '.')
                    {
                        target.pop_back();
                    }
                    const auto found = std::find_if(config.Peers.begin(),
                                                    config.Peers.end(),
                                                    [&](const TailPeer& peer)
                                                    {
                                                        std::string name = peer.Name;
                                                        if (!name.empty() && name.back() == '.')
                                                        {
                                                            name.pop_back();
                                                        }
                                                        const std::size_t dot = name.find('.');
                                                        return peer.Address == target ||
                                                               name == target ||
                                                               name.substr(0, dot) == target;
                                                    });
                    tailgate::crypto::Bytes32 nodeKey{};
                    bool hasNodeKey = false;
                    if (found != config.Peers.end() && found->Key.rfind("nodekey:", 0) == 0)
                    {
                        const std::vector<std::uint8_t> bytes =
                            tailgate::crypto::HexToBytes(found->Key.substr(8));
                        if (bytes.size() == nodeKey.size())
                        {
                            std::copy(bytes.begin(), bytes.end(), nodeKey.begin());
                            hasNodeKey = true;
                        }
                    }
                    const bool tsmp = pingRequest.Tsmp;
                    const std::optional<tailgate::crypto::Bytes32> discoKey =
                        hasNodeKey ? peerDiscoKey(nodeKey) : std::nullopt;
                    if (found == config.Peers.end() || !hasNodeKey || (!tsmp && !discoKey))
                    {
                        tailgate::linux_frontend::PingResponse response{};
                        tailgate::linux_frontend::SendPingResponse(
                            pingServer.Fd, client, clientLength, response);
                    }
                    else
                    {
                        PendingRelayPing pending;
                        pending.Peer = nodeKey;
                        pending.Tsmp = tsmp;
                        pending.Client = client;
                        pending.ClientLength = clientLength;
                        pending.Started = std::chrono::steady_clock::now();
                        pending.TimeoutSeconds = std::max(1, pingRequest.TimeoutSeconds);
                        pending.Name = found->Name;
                        pending.Address = found->Address;
                        pending.Relay = relayHostName;
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
                            pending.DiscoTransaction = disco.NewTransactionId();
                        }
                        pendingPings.push_back(std::move(pending));
                        const PendingRelayPing& queued = pendingPings.back();
                        if (tsmp)
                        {
                            queueTransportPackets(router.Send(tailgate::net::packet::BuildTsmpPing(
                                Ipv4ToHostOrder(config.SelfAddress),
                                Ipv4ToHostOrder(found->Address),
                                queued.TsmpToken)));
                        }
                        else
                        {
                            queueDisco(queued.Peer,
                                       disco.BuildPing(*discoKey, queued.DiscoTransaction));
                        }
                    }
                }
            }
            if (event.Kind == DataplaneEventKind::LocalDns && (events[index].events & EPOLLIN) != 0)
            {
                sockaddr_in client{};
                std::vector<std::uint8_t> dnsPayload = ReceiveUdp(localDns.Fd, &client);
                if (dnsPayload.size() >= 2)
                {
                    const std::uint16_t dnsId =
                        (static_cast<std::uint16_t>(dnsPayload[0]) << 8U) | dnsPayload[1];
                    const std::uint16_t sourcePort = ntohs(client.sin_port);
                    const auto [resolverText, throughTailnet] = selectDnsResolver(dnsPayload);
                    const std::uint32_t resolver = Ipv4ToHostOrder(resolverText);
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
                    if (throughTailnet)
                    {
                        queueTransportPackets(router.Send(tailgate::net::packet::BuildUdpPacket(
                            Ipv4ToHostOrder(config.SelfAddress),
                            resolver,
                            sourcePort,
                            53,
                            dnsPayload)));
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
            if (event.Kind == DataplaneEventKind::UpstreamDns &&
                (events[index].events & EPOLLIN) != 0)
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
            if (event.Kind == DataplaneEventKind::Control &&
                (((events[index].events & EPOLLIN) != 0) ||
                 (((events[index].events & EPOLLOUT) != 0) && tls.ReadNeedsWrite())) &&
                !(tls.WriteNeedsRead() && !socketOutput.empty()))
            {
                for (std::size_t read = 0; read < MaximumPacketsPerDescriptorCycle; ++read)
                {
                    const std::optional<std::vector<std::uint8_t>> input =
                        tls.TryReadSome(16U * 1024U);
                    if (!input)
                    {
                        break;
                    }
                    if (input->empty())
                    {
                        throw std::runtime_error("tailgate relay closed");
                    }
                    decoder.Feed(*input);
                    while (std::optional<tailgate::hosted::Frame> frame = decoder.Next())
                    {
                        if (frame->Type == tailgate::hosted::MessageType::ServerPacket)
                        {
                            const tailgate::hosted::PeerPacket transportPacket =
                                tailgate::hosted::DecodePeerPacket(frame->Payload);
                            if (transportPacket.Disco)
                            {
                                handleDisco(transportPacket);
                                continue;
                            }
                            tailgate::wgengine::wireguard::WireGuardRouter::ReceiveResult received =
                                router.Receive(transportPacket.Peer, transportPacket.Payload);
                            queueTransportPackets(std::move(received.Outbound));
                            for (std::vector<std::uint8_t>& plaintext : received.Plaintext)
                            {
                                handlePlaintext(std::move(plaintext));
                            }
                        }
                        else if (frame->Type == tailgate::hosted::MessageType::NetworkMap)
                        {
                            applyNetworkMap(tailgate::hosted::DecodeNetworkConfig(frame->Payload));
                        }
                        else if (frame->Type == tailgate::hosted::MessageType::DerpChallenge)
                        {
                            const tailgate::hosted::DerpAuthenticationChallenge challenge =
                                tailgate::hosted::DecodeDerpChallenge(frame->Payload);
                            queueFrame(tailgate::hosted::Frame{
                                .Type = tailgate::hosted::MessageType::DerpResponse,
                                .Payload = tailgate::hosted::EncodeDerpResponse(
                                    tailgate::hosted::DerpAuthenticationResponse{
                                        .RequestId = challenge.RequestId,
                                        .ClientInfo = tailgate::derp::DerpClient::BuildClientInfo(
                                            nodePrivateKey,
                                            request.NodePublicKey,
                                            challenge.ServerKey)})});
                        }
                        else if (frame->Type == tailgate::hosted::MessageType::Heartbeat)
                        {
                            // The server drives the heartbeat; answering proves this side of
                            // the Funnel stream is alive. DERP liveness is maintained by this
                            // client's own timers, so fold the reply into the next scheduled
                            // heartbeat slot instead of doubling the cadence.
                            queueFrame(tailgate::hosted::Frame{
                                .Type = tailgate::hosted::MessageType::Heartbeat, .Payload = {}});
                            nextHeartbeat =
                                std::chrono::steady_clock::now() + RelayHeartbeatInterval;
                        }
                    }
                }
                updateSocketEvents();
            }
            if (event.Kind == DataplaneEventKind::Maintenance &&
                (events[index].events & EPOLLIN) != 0)
            {
                DrainTimerFd(maintenanceTimer.Fd);
                queueTransportPackets(router.UpdateTimers());
                const auto now = std::chrono::steady_clock::now();
                if (now >= nextHeartbeat)
                {
                    queueFrame(tailgate::hosted::Frame{
                        .Type = tailgate::hosted::MessageType::Heartbeat, .Payload = {}});
                    nextHeartbeat = now + RelayHeartbeatInterval;
                }
                if (now >= nextDiscoProbe)
                {
                    for (const tailgate::hosted::PeerPacket& probe :
                         tailgate::hosted::BuildDiscoProbes(disco, config.Peers))
                    {
                        queueFrame(tailgate::hosted::Frame{
                            .Type = tailgate::hosted::MessageType::ClientPacket,
                            .Payload = tailgate::hosted::EncodePeerPacket(probe),
                        });
                    }
                    nextDiscoProbe =
                        now + tailgate::wgengine::magicsock::PeerPathState::DirectProbeInterval;
                }
                for (PendingRelayPing& pending : pendingPings)
                {
                    if (pending.ClientLength != 0 &&
                        now - pending.Started >= std::chrono::seconds(pending.TimeoutSeconds))
                    {
                        completePing(pending, false, 0);
                    }
                }
                pendingPings.erase(std::remove_if(pendingPings.begin(),
                                                  pendingPings.end(),
                                                  [](const PendingRelayPing& pending)
                                                  {
                                                      return pending.ClientLength == 0;
                                                  }),
                                   pendingPings.end());
                pendingDns.erase(std::remove_if(pendingDns.begin(),
                                                pendingDns.end(),
                                                [&](const PendingRelayDns& pending)
                                                {
                                                    return now - pending.Started >=
                                                           PendingDnsTimeout;
                                                }),
                                 pendingDns.end());
            }
            if (event.Kind == DataplaneEventKind::Control && !socketOutput.empty() &&
                !tls.ReadNeedsWrite() &&
                (((events[index].events & EPOLLOUT) != 0) ||
                 (((events[index].events & EPOLLIN) != 0) && tls.WriteNeedsRead())))
            {
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
                        updateSocketEvents();
                    }
                }
            }
            if (event.Kind == DataplaneEventKind::Tun && (events[index].events & EPOLLOUT) != 0 &&
                !tunOutput.empty())
            {
                const std::vector<std::uint8_t>& packet = tunOutput.front();
                const ssize_t written = write(tun.Fd, packet.data(), packet.size());
                if (written == static_cast<ssize_t>(packet.size()))
                {
                    tunOutputBytes -= packet.size();
                    tunOutput.pop_front();
                    updateTunEvents();
                }
            }
        }
    }
    if (StopRequested)
    {
        transport.SetNonBlocking(false);
        tailgate::hosted::WriteFrame(
            tls,
            tailgate::hosted::Frame{.Type = tailgate::hosted::MessageType::Shutdown,
                                    .Payload = {}});
    }
    unlink(tailgate::linux_frontend::PingSocketPath().c_str());
}

class ControlDnsPublisher final : public tailgate::serve::acme::IChallengePublisher
{
public:
    explicit ControlDnsPublisher(tailgate::control::client::ControlClient& control)
        : m_control(control)
    {
    }

    void PublishDnsTxt(const std::string& name, const std::string& value) override
    {
        tailgate::base::Log(
            tailgate::base::LogLevel::Info, "acme", "publishing DNS-01 record " + name);
        m_control.SetDnsTxt(name, value);
    }

private:
    tailgate::control::client::ControlClient& m_control;
};

void RunConnection(
    const std::string& authKey,
    tailgate::control::client::HostInfo host,
    const tailgate::crypto::Bytes32& machineKey,
    const tailgate::crypto::Bytes32& nodePrivateKey,
    bool acceptDns,
    const std::string& exitNode,
    int funnelPort,
    int funnelLocalPort,
    int exposePort,
    tailgate::linux_frontend::DaemonStatus& status,
    int& readyFd,
    int packetFd = -1,
    const tailgate::crypto::Bytes32* discoPrivateKey = nullptr,
    const tailgate::crypto::Bytes32* nodePublicKey = nullptr,
    bool configureHost = true,
    bool persistStatus = true,
    std::function<void(const tailgate::types::netmap::NetworkConfig&)> registered = {},
    std::function<void(const tailgate::types::netmap::NetworkConfig&)> updated = {},
    tailgate::derp::DerpClient::Authenticator derpAuthenticator = {},
    std::function<void()> registrationAccepted = {},
    const std::string& followupUrl = {},
    std::function<void(const tailgate::control::client::RegistrationResult&)> registrationPending =
        {},
    const std::string& reauthorizationKey = {})
{
    const tailgate::serve::FunnelConfig funnel =
        tailgate::serve::TlsTerminatedTcpFunnel(funnelPort, funnelLocalPort);
    tailgate::serve::ApplyToHostInfo(funnel, host);
    if (tailgate::serve::IsEnabled(funnel))
    {
        host.Services.push_back(tailgate::control::client::HostService{.Protocol = "peerapi4",
                                                                       .Port = FunnelPeerApiPort});
        host.Services.push_back(tailgate::control::client::HostService{.Protocol = "peerapi6",
                                                                       .Port = FunnelPeerApiPort});
        host.Services.push_back(
            tailgate::control::client::HostService{.Protocol = "peerapi-dns-proxy", .Port = 1});
        tailgate::base::Log(
            tailgate::base::LogLevel::Info,
            "control",
            std::format("advertising funnel hostinfo: ingress={} wire-ingress={} peerapi-port={}",
                        host.IngressEnabled ? 1 : 0,
                        host.WireIngress ? 1 : 0,
                        FunnelPeerApiPort));
    }
    std::unique_ptr<tailgate::control::client::ControlClient> dialedControl;
    tailgate::linux_frontend::DialedControlStream controlStream =
        tailgate::linux_frontend::DialControl(
            DefaultRouteInterface(),
            [&](tailgate::base::IByteStream& dialedStream)
            {
                dialedControl = nodePublicKey != nullptr
                                    ? std::make_unique<tailgate::control::client::ControlClient>(
                                          dialedStream,
                                          machineKey,
                                          tailgate::control::client::ExternalNodePublicKey{
                                              .Value = *nodePublicKey},
                                          host)
                                    : std::make_unique<tailgate::control::client::ControlClient>(
                                          dialedStream, machineKey, nodePrivateKey, host);
            });
    tailgate::control::client::ControlClient& control = *dialedControl;
    if (discoPrivateKey != nullptr)
    {
        control.SetDiscoPrivateKey(*discoPrivateKey);
    }
    const std::string underlayInterface = DefaultRouteInterface();
    UniqueFd advertisedUdp = OpenUdpSocket(underlayInterface);
    const std::string localEndpoint =
        std::format("{}:{}",
                    tailgate::net::packet::FormatIpv4(InterfaceIpv4Address(underlayInterface)),
                    SocketPort(advertisedUdp.Fd));
    std::vector<tailgate::control::client::MapEndpoint> advertisedEndpoints{
        tailgate::control::client::MapEndpoint{
            .AddressPort = localEndpoint, .Type = tailgate::control::client::EndpointType::Local}};
    control.SetEndpoints(advertisedEndpoints);
    tailgate::base::Log(
        tailgate::base::LogLevel::Info,
        "control",
        std::format("advertising endpoint {} on {}", localEndpoint, underlayInterface));
    const tailgate::control::client::RegistrationOptions registrationOptions =
        BuildRegistrationOptions(followupUrl, reauthorizationKey, registrationPending);
    tailgate::control::client::RegistrationResult registration =
        control.RegisterUntilAuthorized(authKey, registrationOptions);
    if (!registration.Network)
    {
        throw std::runtime_error("control registration completed without a network map");
    }
    tailgate::types::netmap::NetworkConfig config = std::move(*registration.Network);
    if (registrationAccepted)
    {
        registrationAccepted();
    }
    if (configureHost)
    {
        UpdateRelayHostNetworkMap(config);
    }
    if (registered)
    {
        registered(config);
    }
    if (tailgate::serve::IsEnabled(funnel))
    {
        tailgate::base::Log(tailgate::base::LogLevel::Info,
                            "control",
                            "node capabilities=" + CapabilitySummary(config.Capabilities));
        if (!tailgate::types::netmap::HasCapability(config, "https") ||
            !tailgate::types::netmap::HasCapability(config, "funnel"))
        {
            const tailgate::control::client::FeatureEnablement enablement =
                control.QueryFeature("funnel");
            if (!enablement.Complete)
            {
                throw std::runtime_error(std::format("{}\ncapabilities={}",
                                                     FeatureEnablementSummary(enablement),
                                                     CapabilitySummary(config.Capabilities)));
            }
            config = control.RequestNetworkMap();
            tailgate::base::Log(tailgate::base::LogLevel::Info,
                                "control",
                                "node capabilities after Funnel enablement=" +
                                    CapabilitySummary(config.Capabilities));
        }
        if (!tailgate::types::netmap::HasCapability(config, "https"))
        {
            throw std::runtime_error("Funnel not available; HTTPS capability is not enabled; "
                                     "capabilities=" +
                                     CapabilitySummary(config.Capabilities));
        }
        if (!tailgate::types::netmap::HasCapability(config, "funnel"))
        {
            throw std::runtime_error("Funnel not available; node does not have funnel capability; "
                                     "capabilities=" +
                                     CapabilitySummary(config.Capabilities));
        }
        if (!tailgate::types::netmap::AllowsFunnelPort(config, funnel.Port))
        {
            throw std::runtime_error(
                std::format("Funnel not available; port {} is not allowed by control; "
                            "capabilities={}",
                            funnel.Port,
                            CapabilitySummary(config.Capabilities)));
        }
    }
    std::string funnelCertificatePem;
    std::string funnelPrivateKeyPem;
    if (tailgate::serve::IsEnabled(funnel))
    {
        std::string certificateDomain = config.SelfName;
        while (!certificateDomain.empty() && certificateDomain.back() == '.')
        {
            certificateDomain.pop_back();
        }
        if (std::find(config.CertDomains.begin(), config.CertDomains.end(), certificateDomain) ==
            config.CertDomains.end())
        {
            throw std::runtime_error("control did not authorize an HTTPS certificate for " +
                                     certificateDomain);
        }
        constexpr std::chrono::hours RenewalWindow = std::chrono::hours(24 * 30);
        tailgate::serve::acme::MbedTlsCrypto crypto;
        std::optional<tailgate::linux_frontend::AcmeState> cached =
            tailgate::linux_frontend::ReadAcmeState();
        if (cached && cached->Domain == certificateDomain &&
            crypto.CertificateValidFor(cached->CertificatePem, RenewalWindow))
        {
            funnelCertificatePem = cached->CertificatePem;
            funnelPrivateKeyPem = cached->PrivateKeyPem;
            tailgate::base::Log(tailgate::base::LogLevel::Info,
                                "acme",
                                "using cached certificate for " + certificateDomain);
        }
        else
        {
            tailgate::linux_frontend::LinuxAcmeHttpClient http;
            tailgate::linux_frontend::LinuxAcmeWaiter waiter;
            ControlDnsPublisher publisher(control);
            tailgate::serve::acme::AcmeClient acme(http, crypto, publisher, waiter);
            const std::optional<std::string> accountKey =
                cached && !cached->AccountPrivateKey.empty()
                    ? std::optional<std::string>(cached->AccountPrivateKey)
                    : std::nullopt;
            tailgate::base::Log(tailgate::base::LogLevel::Info,
                                "acme",
                                "requesting certificate for " + certificateDomain);
            const tailgate::serve::acme::Certificate issued =
                acme.Issue(certificateDomain, accountKey);
            funnelCertificatePem = issued.CertificatePem;
            funnelPrivateKeyPem = issued.PrivateKeyPem;
            tailgate::linux_frontend::WriteAcmeState(
                tailgate::linux_frontend::AcmeState{.Domain = certificateDomain,
                                                    .AccountPrivateKey = acme.AccountPrivateKey(),
                                                    .CertificatePem = funnelCertificatePem,
                                                    .PrivateKeyPem = funnelPrivateKeyPem});
        }
    }
    int derpRegion = config.DerpRegion;
    std::string derpHost = config.DerpHost;
    if (!exitNode.empty())
    {
        const auto selectedExitNode =
            tailgate::types::netmap::FindExitNode(config.Peers, exitNode, true);
        if (!selectedExitNode)
        {
            throw std::runtime_error("exit node was not found in the network map: " + exitNode);
        }
        const tailgate::types::netmap::PeerConfig& peer = config.Peers[*selectedExitNode];
        if (peer.DerpRegion == 0 || peer.DerpHost.empty())
        {
            throw std::runtime_error("exit node has no usable DERP region: " + exitNode);
        }
        derpRegion = peer.DerpRegion;
        derpHost = peer.DerpHost;
    }
    if (derpRegion != 0 && !derpHost.empty())
    {
        try
        {
            if (std::optional<std::string> stunEndpoint =
                    QueryStunEndpoint(advertisedUdp.Fd,
                                      config.StunHost.empty() ? derpHost : config.StunHost,
                                      config.StunPort))
            {
                advertisedEndpoints.insert(
                    advertisedEndpoints.begin(),
                    tailgate::control::client::MapEndpoint{
                        .AddressPort = *stunEndpoint,
                        .Type = tailgate::control::client::EndpointType::Stun});
                control.SetEndpoints(advertisedEndpoints);
                tailgate::base::Log(
                    tailgate::base::LogLevel::Info,
                    "control",
                    std::format("advertising STUN endpoint {} via {}", *stunEndpoint, derpHost));
            }
        }
        catch (const std::exception& error)
        {
            tailgate::base::Log(tailgate::base::LogLevel::Warning,
                                "control",
                                "failed to discover STUN endpoint: " + std::string(error.what()));
        }
    }
    // Streaming map requests are read-only at modern capability versions, so control may ignore
    // their Hostinfo. Publish the home DERP and endpoints before opening the map stream.
    control.UpdateHostInfo(derpRegion);
    if (!registration.NetworkMapStreaming)
    {
        control.SetPreferredDerp(derpRegion);
    }
    controlStream.Stream->SetNonBlocking(true);
    std::unique_ptr<tailgate::linux_frontend::LinuxRelayServer> relayServer;
    if (configureHost && exposePort != 0)
    {
        relayServer = std::make_unique<tailgate::linux_frontend::LinuxRelayServer>(
            ExposeLocalPort,
            [domain = config.Domain,
             relayHostName = DisplayName(config.SelfName),
             relayHostAddress = config.SelfAddress,
             relayPrivateKey = nodePrivateKey,
             relayPublicKey =
                 control.NodePublicKey()](tailgate::base::IByteStream& relay,
                                          const std::function<void()>& closeConnection,
                                          const std::function<void()>& markIdentityVerified)
            {
                RunHostedRelay(relay,
                               domain,
                               relayHostName,
                               relayHostAddress,
                               relayPrivateKey,
                               relayPublicKey,
                               closeConnection,
                               markIdentityVerified);
            });
    }
    const auto handleUpdate = [configureHost, updated = std::move(updated)](
                                  const tailgate::types::netmap::NetworkConfig& next)
    {
        if (configureHost)
        {
            UpdateRelayHostNetworkMap(next);
        }
        if (updated)
        {
            updated(next);
        }
    };
    const std::optional<tailgate::crypto::Bytes32> externalNodePublicKey =
        nodePublicKey == nullptr ? std::nullopt
                                 : std::optional<tailgate::crypto::Bytes32>(*nodePublicKey);
    const tailgate::crypto::Bytes32 reconnectDiscoPrivateKey = control.DiscoPrivateKey();
    const auto reconnectControl = [host,
                                   machineKey,
                                   nodePrivateKey,
                                   externalNodePublicKey,
                                   reconnectDiscoPrivateKey,
                                   advertisedEndpoints,
                                   derpRegion]()
    {
        auto session = std::make_unique<LiveControlSession>();
        tailgate::linux_frontend::DialedControlStream dialed =
            tailgate::linux_frontend::DialControl(
                DefaultRouteInterface(),
                [&](tailgate::base::IByteStream& stream)
                {
                    session->Control =
                        externalNodePublicKey
                            ? std::make_unique<tailgate::control::client::ControlClient>(
                                  stream,
                                  machineKey,
                                  tailgate::control::client::ExternalNodePublicKey{
                                      .Value = *externalNodePublicKey},
                                  host)
                            : std::make_unique<tailgate::control::client::ControlClient>(
                                  stream, machineKey, nodePrivateKey, host);
                });
        session->Stream = std::move(dialed.Stream);
        session->Control->SetDiscoPrivateKey(reconnectDiscoPrivateKey);
        session->Control->SetEndpoints(advertisedEndpoints);
        // Reconnect runs on ControlUpdateWorker's background thread. Receive the stream's first
        // full map before publishing the replacement socket so callers waiting for a forced
        // refresh cannot mistake a transport-only reconnect for a refreshed authorization view.
        // This request is explicitly read-only: a regular one-shot request creates a transient
        // ingress generation that Funnel later closes.
        session->InitialNetwork = session->Control->RequestNetworkMap();
        session->Control->SetPreferredDerp(derpRegion);
        session->Stream->SetNonBlocking(true);
        return session;
    };
    StartTunnel(nodePrivateKey,
                control.NodePublicKey(),
                control.DiscoPrivateKey(),
                config.SelfAddress,
                FirstIpv6Address(config.SelfAddresses),
                config.SelfName,
                config.MagicDnsDomain.empty() ? config.Domain : config.MagicDnsDomain,
                config.DnsResolver,
                config.DnsDomains,
                config.DnsDefaultResolvers,
                config.DnsRoutes,
                config.Peers,
                derpRegion,
                derpHost,
                exitNode,
                acceptDns,
                funnel,
                funnelCertificatePem,
                funnelPrivateKeyPem,
                &control,
                controlStream.Stream->NativeHandle(),
                advertisedUdp.Fd,
                reconnectControl,
                status,
                readyFd,
                packetFd,
                configureHost,
                persistStatus,
                nodePublicKey != nullptr,
                -1,
                handleUpdate,
                std::move(derpAuthenticator));
}

struct ActiveRelayConnection
{
    std::function<void()> CloseConnection;
    std::uint64_t NodeId = 0;
    std::mutex CompletionMutex;
    std::condition_variable CompletionChanged;
    bool Completed = false;

    void Complete()
    {
        {
            std::lock_guard lock(CompletionMutex);
            Completed = true;
        }
        CompletionChanged.notify_all();
    }

    bool WaitForCompletion(std::chrono::seconds timeout)
    {
        std::unique_lock lock(CompletionMutex);
        return CompletionChanged.wait_for(lock,
                                          timeout,
                                          [&]()
                                          {
                                              return Completed;
                                          });
    }
};

class RelayConnectionCompletionGuard
{
public:
    explicit RelayConnectionCompletionGuard(std::shared_ptr<ActiveRelayConnection> profile)
        : Profile(std::move(profile))
    {
    }

    ~RelayConnectionCompletionGuard()
    {
        Profile->Complete();
    }

private:
    std::shared_ptr<ActiveRelayConnection> Profile;
};

std::mutex ActiveRelayConnectionsMutex;
std::map<std::string, std::weak_ptr<ActiveRelayConnection>> ActiveRelayConnections;
std::mutex RelayHostMapMutex;
std::condition_variable RelayHostMapChanged;
std::string RelayHostTailnet;
std::string RelayHostName;

struct VisibleRelayNode
{
    std::uint64_t NodeId = 0;
    std::string Key;
};

std::vector<VisibleRelayNode> RelayHostVisibleNodes;
std::uint64_t RelayHostMapGeneration = 0;

void UpdateRelayHostNetworkMap(const tailgate::types::netmap::NetworkConfig& config)
{
    std::vector<VisibleRelayNode> visible;
    visible.reserve(config.Peers.size());
    for (const TailPeer& peer : config.Peers)
    {
        if (peer.NodeId != 0)
        {
            visible.push_back(VisibleRelayNode{.NodeId = peer.NodeId, .Key = peer.Key});
        }
    }
    {
        std::lock_guard lock(RelayHostMapMutex);
        RelayHostTailnet = config.Domain;
        RelayHostName = DisplayName(config.SelfName);
        RelayHostVisibleNodes = std::move(visible);
        ++RelayHostMapGeneration;
    }
    RelayHostMapChanged.notify_all();
}

std::optional<std::string> HostedPathForNode(std::uint64_t nodeId)
{
    if (nodeId == 0)
    {
        return std::nullopt;
    }
    std::lock_guard activeLock(ActiveRelayConnectionsMutex);
    const bool active = std::any_of(ActiveRelayConnections.begin(),
                                    ActiveRelayConnections.end(),
                                    [&](const auto& entry)
                                    {
                                        const std::shared_ptr<ActiveRelayConnection> profile =
                                            entry.second.lock();
                                        return profile && profile->NodeId == nodeId;
                                    });
    if (!active)
    {
        return std::nullopt;
    }
    std::lock_guard mapLock(RelayHostMapMutex);
    return "tailgate(" + RelayHostName + ")";
}

bool WaitForHostedNodeVisibility(const std::string& tailnet,
                                 std::uint64_t nodeId,
                                 const tailgate::crypto::Bytes32& nodePublicKey)
{
    constexpr std::chrono::seconds VisibilityTimeout(30);
    std::unique_lock lock(RelayHostMapMutex);
    const auto visible = [&]()
    {
        const std::string key =
            "nodekey:" + tailgate::crypto::BytesToHex(nodePublicKey.data(), nodePublicKey.size());
        return RelayHostTailnet == tailnet && std::any_of(RelayHostVisibleNodes.begin(),
                                                          RelayHostVisibleNodes.end(),
                                                          [&](const VisibleRelayNode& node)
                                                          {
                                                              return node.NodeId == nodeId &&
                                                                     node.Key == key;
                                                          });
    };
    if (visible())
    {
        return true;
    }
    const std::uint64_t generation = RelayHostMapGeneration;
    const int controlFd = RelayHostControlFd.load();
    if (controlFd >= 0)
    {
        tailgate::base::Log(
            tailgate::base::LogLevel::Info,
            "relay",
            "hosted node is absent from the live map; requesting a full control map");
        shutdown(controlFd, SHUT_RDWR);
    }
    const bool found = RelayHostMapChanged.wait_for(lock, VisibilityTimeout, visible);
    if (!found && RelayHostMapGeneration == generation)
    {
        tailgate::base::Log(tailgate::base::LogLevel::Warning,
                            "relay",
                            "control map did not refresh while checking hosted node visibility");
    }
    return found;
}

void RunHostedRelay(tailgate::base::IByteStream& stream,
                    const std::string& expectedDomain,
                    const std::string& relayHostName,
                    const std::string& relayHostAddress,
                    const tailgate::crypto::Bytes32& relayPrivateKey,
                    const tailgate::crypto::Bytes32& relayPublicKey,
                    const std::function<void()>& closeConnection,
                    const std::function<void()>& markIdentityVerified)
{
    tailgate::hosted::Decoder decoder;
    const tailgate::crypto::Bytes32 serverNonce = tailgate::crypto::GeneratePrivateKey();
    tailgate::hosted::WriteFrame(
        stream,
        tailgate::hosted::Frame{
            .Type = tailgate::hosted::MessageType::ServerChallenge,
            .Payload = tailgate::hosted::EncodeChallenge(tailgate::hosted::Challenge{
                .RelayPublicKey = relayPublicKey, .ServerNonce = serverNonce})});
    const tailgate::hosted::Frame authenticationFrame =
        tailgate::hosted::ReadFrame(stream, decoder);
    if (authenticationFrame.Type != tailgate::hosted::MessageType::Authenticate)
    {
        throw std::runtime_error("relay client did not authenticate first");
    }
    const tailgate::hosted::Authentication authentication =
        tailgate::hosted::DecodeAuthentication(authenticationFrame.Payload);
    const tailgate::crypto::Bytes32 expectedProof = tailgate::hosted::CreateClientProof(
        relayPrivateKey, authentication.NodePublicKey, serverNonce, authentication.ClientNonce);
    const bool proofValid =
        tailgate::hosted::ProofMatches(expectedProof, authentication.ClientProof);
    const bool tailnetMatches = authentication.Tailnet == expectedDomain;
    const bool nodeVisible = proofValid && tailnetMatches &&
                             WaitForHostedNodeVisibility(authentication.Tailnet,
                                                         authentication.NodeId,
                                                         authentication.NodePublicKey);
    if (!proofValid || !tailnetMatches || !nodeVisible)
    {
        tailgate::base::Log(
            tailgate::base::LogLevel::Warning,
            "relay",
            std::format("rejecting hosted authentication node-id={} proof={} tailnet={} "
                        "visibility={}",
                        authentication.NodeId,
                        proofValid ? "valid" : "invalid",
                        tailnetMatches ? "match" : "mismatch",
                        nodeVisible ? "visible" : "missing"));
        tailgate::hosted::WriteFrame(
            stream,
            tailgate::hosted::Frame{
                .Type = tailgate::hosted::MessageType::Rejected,
                .Payload = tailgate::hosted::EncodeRejection(tailgate::hosted::Rejection{
                    .Reason = "node authentication or tailnet visibility check failed"})});
        return;
    }

    std::mutex writeMutex;
    const auto writeFrame = [&](tailgate::hosted::Frame frame)
    {
        std::lock_guard lock(writeMutex);
        tailgate::hosted::WriteFrame(stream, frame);
    };
    writeFrame(
        {.Type = tailgate::hosted::MessageType::Authenticated,
         .Payload = tailgate::hosted::EncodeSession(tailgate::hosted::Session{
             .Tailnet = authentication.Tailnet,
             .RelayHostName = relayHostName,
             .RelayHostAddress = relayHostAddress,
             .ServerProof = tailgate::hosted::CreateServerProof(relayPrivateKey,
                                                                authentication.NodePublicKey,
                                                                serverNonce,
                                                                authentication.ClientNonce)})});

    const tailgate::hosted::Frame mapFrame = tailgate::hosted::ReadFrame(stream, decoder);
    if (mapFrame.Type != tailgate::hosted::MessageType::NetworkMap)
    {
        throw std::runtime_error("relay client did not provide its network map");
    }
    tailgate::types::netmap::NetworkConfig config =
        tailgate::hosted::DecodeNetworkConfig(mapFrame.Payload);
    tailgate::types::netmap::NetworkConfig dnsConfig = config;
    std::mutex dnsConfigMutex;
    const std::string expectedNodeKey =
        "nodekey:" + tailgate::crypto::BytesToHex(authentication.NodePublicKey.data(),
                                                  authentication.NodePublicKey.size());
    const auto validateMap = [&](const tailgate::types::netmap::NetworkConfig& candidate)
    {
        return candidate.Domain == authentication.Tailnet &&
               candidate.SelfNodeId == authentication.NodeId &&
               candidate.SelfKey == expectedNodeKey;
    };
    if (!validateMap(config))
    {
        throw std::runtime_error("relay network map does not match the authenticated node");
    }
    markIdentityVerified();

    const std::string profileKey = tailgate::crypto::BytesToHex(
        authentication.NodePublicKey.data(), authentication.NodePublicKey.size());
    const auto active = std::make_shared<ActiveRelayConnection>();
    RelayConnectionCompletionGuard completionGuard(active);
    active->CloseConnection = closeConnection;
    active->NodeId = authentication.NodeId;
    std::shared_ptr<ActiveRelayConnection> previous;
    {
        std::lock_guard lock(ActiveRelayConnectionsMutex);
        previous = ActiveRelayConnections[profileKey].lock();
        ActiveRelayConnections[profileKey] = active;
    }
    if (previous)
    {
        constexpr std::chrono::seconds ReplacementTimeout(30);
        previous->CloseConnection();
        if (!previous->WaitForCompletion(ReplacementTimeout))
        {
            throw std::runtime_error("previous relay connection did not stop during replacement");
        }
    }
    const auto unregisterActive = [&]()
    {
        std::lock_guard lock(ActiveRelayConnectionsMutex);
        const auto found = ActiveRelayConnections.find(profileKey);
        if (found != ActiveRelayConnections.end() && found->second.lock() == active)
        {
            ActiveRelayConnections.erase(found);
        }
    };

    int packets[2]{};
    int maps[2]{};
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, packets) != 0 ||
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, maps) != 0)
    {
        unregisterActive();
        throw std::runtime_error("relay transport socketpair failed: " +
                                 std::string(std::strerror(errno)));
    }
    UniqueFd relayPackets(packets[0]);
    UniqueFd brokerPackets(packets[1]);
    UniqueFd relayMaps(maps[0]);
    UniqueFd brokerMaps(maps[1]);
    std::atomic<bool> stopping = false;
    std::mutex derpMutex;
    std::condition_variable derpChanged;
    std::mutex clientReadyMutex;
    std::condition_variable clientReadyChanged;
    bool clientReady = false;
    std::uint64_t nextDerpRequestId = 1;
    std::map<std::uint64_t, std::optional<std::vector<std::uint8_t>>> derpResponses;
    const tailgate::derp::DerpClient::Authenticator derpAuthenticator =
        [&](const tailgate::derp::DerpClient::Key& serverKey)
    {
        std::uint64_t requestId = 0;
        {
            std::lock_guard lock(derpMutex);
            requestId = nextDerpRequestId++;
            derpResponses.emplace(requestId, std::nullopt);
        }
        writeFrame({.Type = tailgate::hosted::MessageType::DerpChallenge,
                    .Payload = tailgate::hosted::EncodeDerpChallenge(
                        tailgate::hosted::DerpAuthenticationChallenge{.RequestId = requestId,
                                                                      .ServerKey = serverKey})});
        constexpr std::chrono::seconds AuthenticationTimeout(30);
        std::unique_lock lock(derpMutex);
        const bool completed = derpChanged.wait_for(
            lock,
            AuthenticationTimeout,
            [&]()
            {
                const auto found = derpResponses.find(requestId);
                return stopping || (found != derpResponses.end() && found->second.has_value());
            });
        const auto found = derpResponses.find(requestId);
        if (!completed || found == derpResponses.end() || !found->second)
        {
            derpResponses.erase(requestId);
            throw std::runtime_error("relayed DERP authentication timed out");
        }
        std::vector<std::uint8_t> response = std::move(*found->second);
        derpResponses.erase(found);
        return response;
    };

    std::thread clientReader(
        [&]()
        {
            try
            {
                while (!stopping)
                {
                    const tailgate::hosted::Frame frame =
                        tailgate::hosted::ReadFrame(stream, decoder);
                    if (frame.Type == tailgate::hosted::MessageType::ClientPacket)
                    {
                        if (send(relayPackets.Fd,
                                 frame.Payload.data(),
                                 frame.Payload.size(),
                                 MSG_NOSIGNAL) < 0)
                        {
                            throw std::runtime_error("relay packet forwarding failed");
                        }
                    }
                    else if (frame.Type == tailgate::hosted::MessageType::NetworkMap)
                    {
                        const tailgate::types::netmap::NetworkConfig next =
                            tailgate::hosted::DecodeNetworkConfig(frame.Payload);
                        if (!validateMap(next))
                        {
                            throw std::runtime_error("relay network-map identity changed");
                        }
                        if (send(relayMaps.Fd,
                                 frame.Payload.data(),
                                 frame.Payload.size(),
                                 MSG_NOSIGNAL) < 0)
                        {
                            throw std::runtime_error("relay network-map forwarding failed");
                        }
                        {
                            std::lock_guard lock(dnsConfigMutex);
                            dnsConfig = next;
                        }
                    }
                    else if (frame.Type == tailgate::hosted::MessageType::TailnetDnsQuery)
                    {
                        std::optional<std::vector<std::uint8_t>> response;
                        {
                            std::lock_guard lock(dnsConfigMutex);
                            const std::optional<std::uint32_t> expectedSource =
                                tailgate::net::packet::ParseIpv4(dnsConfig.SelfAddress);
                            const std::optional<tailgate::net::packet::Ipv4UdpDatagram> query =
                                tailgate::net::packet::ParseIpv4UdpDatagram(frame.Payload);
                            if (!expectedSource || !query || query->Source != *expectedSource)
                            {
                                throw std::runtime_error(
                                    "relay Tailnet DNS query has an invalid source");
                            }
                            response = tailgate::net::dns::BuildTailnetDnsResponse(dnsConfig,
                                                                                   frame.Payload);
                        }
                        if (!response)
                        {
                            throw std::runtime_error("relay Tailnet DNS query is malformed");
                        }
                        const std::optional<tailgate::net::packet::Ipv4UdpDatagram> query =
                            tailgate::net::packet::ParseIpv4UdpDatagram(frame.Payload);
                        const std::optional<std::string> name =
                            query ? tailgate::net::dns::DnsQueryName(query->Payload) : std::nullopt;
                        tailgate::base::Log(
                            tailgate::base::LogLevel::Info,
                            "dns",
                            std::format("answered hosted Tailnet DNS query name={} node-id={}",
                                        name.value_or("<invalid>"),
                                        authentication.NodeId));
                        writeFrame({.Type = tailgate::hosted::MessageType::TailnetDnsResponse,
                                    .Payload = std::move(*response)});
                    }
                    else if (frame.Type == tailgate::hosted::MessageType::DerpResponse)
                    {
                        tailgate::hosted::DerpAuthenticationResponse response =
                            tailgate::hosted::DecodeDerpResponse(frame.Payload);
                        {
                            std::lock_guard lock(derpMutex);
                            const auto found = derpResponses.find(response.RequestId);
                            if (found == derpResponses.end() || found->second)
                            {
                                throw std::runtime_error("unexpected DERP authentication response");
                            }
                            found->second = std::move(response.ClientInfo);
                        }
                        derpChanged.notify_all();
                    }
                    else if (frame.Type == tailgate::hosted::MessageType::Heartbeat)
                    {
                        // The server drives the heartbeat cadence from the writer thread;
                        // a client heartbeat only proves the client side is alive. Replying
                        // here would ping-pong forever with clients that answer heartbeats.
                        {
                            std::lock_guard lock(clientReadyMutex);
                            clientReady = true;
                        }
                        clientReadyChanged.notify_all();
                    }
                    else if (frame.Type == tailgate::hosted::MessageType::Shutdown)
                    {
                        break;
                    }
                }
            }
            catch (const std::exception& error)
            {
                tailgate::base::Log(tailgate::base::LogLevel::Info,
                                    "relay",
                                    "hosted client reader stopped: " + std::string(error.what()));
            }
            stopping = true;
            derpChanged.notify_all();
            clientReadyChanged.notify_all();
            shutdown(relayPackets.Fd, SHUT_RDWR);
            shutdown(relayMaps.Fd, SHUT_RDWR);
        });
    std::thread serverWriter(
        [&]()
        {
            try
            {
                std::vector<std::uint8_t> packet(RelayPacketBufferSize);
                UniqueFd heartbeatTimer = CreateTimerFd(RelayHeartbeatInterval);
                while (!stopping)
                {
                    std::array<pollfd, 2> pollers{
                        pollfd{.fd = relayPackets.Fd, .events = POLLIN, .revents = 0},
                        pollfd{.fd = heartbeatTimer.Fd, .events = POLLIN, .revents = 0}};
                    if (poll(pollers.data(), pollers.size(), -1) < 0)
                    {
                        if (errno == EINTR)
                        {
                            continue;
                        }
                        throw std::runtime_error("relay packet poll failed: " +
                                                 std::string(std::strerror(errno)));
                    }
                    if ((pollers[1].revents & POLLIN) != 0)
                    {
                        DrainTimerFd(heartbeatTimer.Fd);
                        // The server drives the heartbeat so clients without their own
                        // timers (UWP) get a periodic opportunity to run WireGuard timers
                        // and send DERP-bound packets.
                        writeFrame(
                            {.Type = tailgate::hosted::MessageType::Heartbeat, .Payload = {}});
                    }
                    if ((pollers[0].revents & (POLLIN | POLLERR | POLLHUP)) == 0)
                    {
                        continue;
                    }
                    const ssize_t received = recv(relayPackets.Fd, packet.data(), packet.size(), 0);
                    if (received <= 0)
                    {
                        break;
                    }
                    writeFrame({.Type = tailgate::hosted::MessageType::ServerPacket,
                                .Payload = std::vector<std::uint8_t>(packet.begin(),
                                                                     packet.begin() + received)});
                }
            }
            catch (const std::exception& error)
            {
                tailgate::base::Log(tailgate::base::LogLevel::Info,
                                    "relay",
                                    "hosted server writer stopped: " + std::string(error.what()));
            }
            stopping = true;
            shutdown(relayPackets.Fd, SHUT_RDWR);
        });

    std::exception_ptr connectionError;
    try
    {
        constexpr std::chrono::seconds DataPathReadyTimeout(45);
        std::unique_lock readyLock(clientReadyMutex);
        const bool ready = clientReadyChanged.wait_for(readyLock,
                                                       DataPathReadyTimeout,
                                                       [&]()
                                                       {
                                                           return clientReady || stopping;
                                                       });
        if (!ready || !clientReady)
        {
            throw std::runtime_error("relay client data path did not become ready");
        }
        readyLock.unlock();
        tailgate::base::Log(
            tailgate::base::LogLevel::Info,
            "relay",
            std::format("hosted client data path ready node-id={}", authentication.NodeId));
        UniqueFd advertisedUdp = OpenUdpSocket(DefaultRouteInterface());
        tailgate::linux_frontend::DaemonStatus hostedStatus;
        int readyFd = -1;
        StartTunnel({},
                    authentication.NodePublicKey,
                    {},
                    config.SelfAddress,
                    FirstIpv6Address(config.SelfAddresses),
                    config.SelfName,
                    config.MagicDnsDomain.empty() ? config.Domain : config.MagicDnsDomain,
                    config.DnsResolver,
                    config.DnsDomains,
                    config.DnsDefaultResolvers,
                    config.DnsRoutes,
                    config.Peers,
                    config.DerpRegion,
                    config.DerpHost,
                    "",
                    false,
                    {},
                    {},
                    {},
                    nullptr,
                    -1,
                    advertisedUdp.Fd,
                    {},
                    hostedStatus,
                    readyFd,
                    brokerPackets.Fd,
                    false,
                    false,
                    true,
                    brokerMaps.Fd,
                    {},
                    derpAuthenticator);
    }
    catch (...)
    {
        connectionError = std::current_exception();
    }
    stopping = true;
    derpChanged.notify_all();
    shutdown(relayPackets.Fd, SHUT_RDWR);
    shutdown(relayMaps.Fd, SHUT_RDWR);
    clientReader.join();
    serverWriter.join();
    unregisterActive();
    if (connectionError)
    {
        std::rethrow_exception(connectionError);
    }
}

std::string ResolveAuthKey(const std::string& value)
{
    if (value.empty())
    {
        return {};
    }
    if (value.rfind("file:", 0) == 0)
    {
        if (value.size() == 5)
        {
            throw std::runtime_error("--auth-key=file: requires a path");
        }
        return tailgate::linux_frontend::ReadTextFile(value.substr(5));
    }
    return value;
}

std::string CurrentLocale()
{
    for (const char* name : {"LC_ALL", "LC_CTYPE", "LANG"})
    {
        if (const char* value = std::getenv(name); value != nullptr && value[0] != '\0')
        {
            return value;
        }
    }
    return "C";
}

void PrintAuthorizationPrompt(const std::string& authorizationUrl,
                              const std::string& backendState,
                              const tailgate::cli::UpOptions& options)
{
    if (backendState == "NeedsMachineAuth")
    {
        std::cerr << "\nTo approve your machine, visit (as admin):\n\n\t" << authorizationUrl
                  << "\n\n";
    }
    else
    {
        std::cerr << "\nTo authenticate, visit:\n\n\t" << authorizationUrl << "\n\n";
    }
    if (!options.Qr)
    {
        return;
    }
    const tailgate::qr::QrCode code = tailgate::qr::EncodeQrCode(authorizationUrl);
    const tailgate::linux_frontend::QrTextFormat format =
        tailgate::linux_frontend::ResolveQrTextFormat(options.QrFormat, CurrentLocale());
    std::cerr << tailgate::linux_frontend::RenderQrCode(code, format) << '\n';
}

int RunDown()
{
    const auto existing = tailgate::linux_frontend::ReadDaemonStatus();
    if (existing && tailgate::linux_frontend::IsProcessRunning(existing->ProcessId))
    {
        if (kill(existing->ProcessId, SIGTERM) != 0)
        {
            throw std::runtime_error("failed to signal the Tailgate daemon");
        }
        for (int attempt = 0; attempt < 600; ++attempt)
        {
            if (!tailgate::linux_frontend::IsProcessRunning(existing->ProcessId))
            {
                break;
            }
            usleep(100000);
        }
        if (tailgate::linux_frontend::IsProcessRunning(existing->ProcessId))
        {
            throw std::runtime_error("Tailgate did not stop after SIGTERM");
        }
    }
    tailgate::linux_frontend::RestoreResolverConfiguration();
    tailgate::linux_frontend::RemoveResolverBackup();
    tailgate::linux_frontend::RemoveDaemonStatus();
    return 0;
}

int RunLogout()
{
    const std::optional<tailgate::linux_frontend::IdentityState> identity =
        tailgate::linux_frontend::ReadIdentity();
    RunDown();
    if (!identity)
    {
        tailgate::linux_frontend::RemoveProfileState();
        return 0;
    }

    tailgate::control::client::HostInfo host = tailgate::linux_frontend::CollectHostInfo();
    if (!identity->Hostname.empty())
    {
        host.Hostname = identity->Hostname;
    }
    tailgate::linux_frontend::TcpStream stream(
        tailgate::control::base::ControlHandshake::DefaultHost,
        "443",
        DefaultRouteInterface(),
        tailgate::linux_frontend::TcpStream::ControlIoTimeoutSeconds);
    tailgate::net::tls::TlsStream tls(stream,
                                      tailgate::control::base::ControlHandshake::DefaultHost,
                                      tailgate::linux_frontend::SystemCaBundle());
    tailgate::control::client::ControlClient control(
        tls, identity->MachinePrivateKey, identity->NodePrivateKey, host);
    control.Logout();
    tailgate::linux_frontend::RemoveProfileState();
    return 0;
}

tailgate::platform::UpResult RunUp(const tailgate::cli::UpOptions& options)
{
    tailgate::linux_frontend::RemoveLegacyHostedProfiles();
    const tailgate::linux_frontend::SettingsState currentSettings =
        tailgate::linux_frontend::ReadSettings().value_or(
            tailgate::linux_frontend::SettingsState{});
    tailgate::linux_frontend::SettingsState requestedSettings =
        ApplyUpOptions(currentSettings, options);
    if (!requestedSettings.TailgateUrl.empty() && requestedSettings.ExposePort != 0)
    {
        throw std::runtime_error(
            "this node is running expose; stop expose before enabling --tailgate");
    }
    const auto existing = tailgate::linux_frontend::ReadDaemonStatus();
    if (existing && tailgate::linux_frontend::IsProcessRunning(existing->ProcessId))
    {
        const bool restartWithAuth =
            !options.AuthKey.empty() &&
            (!existing->Error.empty() || !existing->AuthorizationUrl.empty() ||
             requestedSettings.TailgateUrl != currentSettings.TailgateUrl);
        tailgate::linux_frontend::WriteSettings(requestedSettings);
        if (restartWithAuth)
        {
            tailgate::base::Log(tailgate::base::LogLevel::Info,
                                "daemon",
                                "restarting failed connection with a supplied auth key");
            if (kill(existing->ProcessId, SIGTERM) != 0)
            {
                throw std::runtime_error("failed to restart the Tailgate daemon");
            }
            for (int attempt = 0; attempt < 600; ++attempt)
            {
                if (!tailgate::linux_frontend::IsProcessRunning(existing->ProcessId))
                {
                    break;
                }
                usleep(100000);
            }
            if (tailgate::linux_frontend::IsProcessRunning(existing->ProcessId))
            {
                throw std::runtime_error("Tailgate did not stop for relay recovery");
            }
            tailgate::linux_frontend::RemoveDaemonStatus();
        }
        else
        {
            if (!existing->AuthorizationUrl.empty())
            {
                PrintAuthorizationPrompt(
                    existing->AuthorizationUrl, existing->BackendState, options);
            }
            if (kill(existing->ProcessId, SIGUSR1) == 0)
            {
                (void)WaitForDaemonReload(static_cast<pid_t>(existing->ProcessId), existing->Error);
                return tailgate::platform::UpResult{.Ready = true};
            }
            tailgate::base::Log(tailgate::base::LogLevel::Warning,
                                "daemon",
                                "stale Tailgate status; starting a new daemon");
            tailgate::linux_frontend::RemoveDaemonStatus();
        }
    }

    tailgate::linux_frontend::RestoreResolverConfiguration();
    tailgate::linux_frontend::SaveResolverConfiguration();

    tailgate::control::client::HostInfo host = tailgate::linux_frontend::CollectHostInfo();
    if (!requestedSettings.Hostname.empty())
    {
        host.Hostname = requestedSettings.Hostname;
    }
    const std::string authKey = ResolveAuthKey(options.AuthKey);
    std::optional<tailgate::linux_frontend::IdentityState> identity =
        tailgate::linux_frontend::ReadIdentity();
    if (identity && requestedSettings.Hostname.empty() && !identity->Hostname.empty())
    {
        host.Hostname = identity->Hostname;
    }
    if (!identity)
    {
        identity = tailgate::linux_frontend::IdentityState{
            .MachinePrivateKey = tailgate::crypto::GeneratePrivateKey(),
            .NodePrivateKey = tailgate::crypto::GeneratePrivateKey(),
            .DiscoPrivateKey = tailgate::crypto::GeneratePrivateKey(),
            .Hostname = host.Hostname};
        tailgate::linux_frontend::WriteIdentity(*identity);
    }
    else
    {
        bool identityChanged = false;
        if (std::all_of(identity->DiscoPrivateKey.begin(),
                        identity->DiscoPrivateKey.end(),
                        [](std::uint8_t byte)
                        {
                            return byte == 0;
                        }))
        {
            identity->DiscoPrivateKey = tailgate::crypto::GeneratePrivateKey();
            identityChanged = true;
        }
        if (!requestedSettings.Hostname.empty() && identity->Hostname != host.Hostname)
        {
            identity->Hostname = host.Hostname;
            identityChanged = true;
        }
        if (identityChanged)
        {
            tailgate::linux_frontend::WriteIdentity(*identity);
        }
    }
    requestedSettings.Hostname = host.Hostname;
    tailgate::linux_frontend::WriteSettings(requestedSettings);

    int readyPipe[2]{};
    if (pipe(readyPipe) != 0)
    {
        throw std::runtime_error("failed to create daemon readiness pipe");
    }

    const pid_t pid = fork();
    if (pid < 0)
    {
        close(readyPipe[0]);
        close(readyPipe[1]);
        throw std::runtime_error("failed to fork Tailgate daemon");
    }
    if (pid > 0)
    {
        close(readyPipe[1]);
        struct sigaction action{};
        action.sa_handler = HandleStartupSignal;
        sigemptyset(&action.sa_mask);
        struct sigaction previousInterrupt{};
        struct sigaction previousTerminate{};
        sigaction(SIGINT, &action, &previousInterrupt);
        sigaction(SIGTERM, &action, &previousTerminate);
        StartupInterrupted = 0;
        StartupDaemonPid = pid;
        char ready = 0;
        ssize_t bytesRead = -1;
        std::string displayedAuthorizationUrl;
        while (!StartupInterrupted && bytesRead < 0)
        {
            pollfd readiness{.fd = readyPipe[0], .events = POLLIN, .revents = 0};
            constexpr int LoginStatusPollMilliseconds = 250;
            const int pollResult = poll(&readiness, 1, LoginStatusPollMilliseconds);
            if (pollResult > 0 && (readiness.revents & (POLLIN | POLLHUP | POLLERR)) != 0)
            {
                bytesRead = read(readyPipe[0], &ready, 1);
            }
            else if (pollResult < 0 && errno != EINTR)
            {
                break;
            }
            const auto currentStatus = tailgate::linux_frontend::ReadDaemonStatus();
            if (currentStatus && !currentStatus->AuthorizationUrl.empty() &&
                currentStatus->AuthorizationUrl != displayedAuthorizationUrl)
            {
                displayedAuthorizationUrl = currentStatus->AuthorizationUrl;
                PrintAuthorizationPrompt(
                    displayedAuthorizationUrl, currentStatus->BackendState, options);
            }
        }
        StartupDaemonPid = 0;
        sigaction(SIGINT, &previousInterrupt, nullptr);
        sigaction(SIGTERM, &previousTerminate, nullptr);
        if (bytesRead != 1)
        {
            ready = 0;
        }
        close(readyPipe[0]);
        if (StartupInterrupted)
        {
            (void)waitpid(pid, nullptr, 0);
            throw std::runtime_error("up interrupted; Tailgate daemon stopped");
        }
        if (ready == '1')
        {
            return tailgate::platform::UpResult{.Ready = true};
        }
        else
        {
            return tailgate::platform::UpResult{.Ready = false};
        }
    }

    close(readyPipe[0]);
    if (setsid() < 0)
    {
        _exit(1);
    }
    umask(0077);
    std::filesystem::create_directories(tailgate::linux_frontend::StateDirectory());
    const std::string logPath = tailgate::linux_frontend::StateDirectory() + "/tailgate.log";
    const int logFd = open(logPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    const int nullFd = open("/dev/null", O_RDONLY);
    if (logFd >= 0)
    {
        (void)dup2(logFd, STDOUT_FILENO);
        (void)dup2(logFd, STDERR_FILENO);
        close(logFd);
    }
    if (nullFd >= 0)
    {
        (void)dup2(nullFd, STDIN_FILENO);
        close(nullFd);
    }

    tailgate::base::SetLogSink(
        [](tailgate::base::LogLevel level, const std::string& component, const std::string& message)
        {
            const auto now = std::chrono::system_clock::now();
            const auto seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);
            const auto milliseconds =
                std::chrono::duration_cast<std::chrono::milliseconds>(now - seconds).count();
            std::osyncstream(std::cerr) << std::format("{:%Y-%m-%dT%H:%M:%S}.{:03}Z [{}] {}: {}\n",
                                                       seconds,
                                                       milliseconds,
                                                       tailgate::base::LogLevelName(level),
                                                       component,
                                                       message)
                                        << std::flush;
        });

    tailgate::base::Log(tailgate::base::LogLevel::Info,
                        "daemon",
                        std::format("started pid={} hostname={} state={}",
                                    getpid(),
                                    host.Hostname,
                                    tailgate::linux_frontend::StateDirectory()));

    std::signal(SIGTERM, HandleStopSignal);
    std::signal(SIGINT, HandleStopSignal);
    std::signal(SIGHUP, HandleStopSignal);
    std::signal(SIGUSR1, HandleReloadSignal);
    std::signal(SIGPIPE, SIG_IGN);

    tailgate::linux_frontend::DaemonStatus status;
    status.ProcessId = getpid();
    status.BackendState = "Starting";
    status.Hostname = host.Hostname;
    status.OperatingSystem = host.OperatingSystem;
    status.OperatingSystemVersion = host.OperatingSystemVersion;
    status.ClientVersion = host.ClientVersion;
    tailgate::linux_frontend::WriteDaemonStatus(status);

    tailgate::control::client::RetryBackoff retryBackoff(std::chrono::seconds(1),
                                                         std::chrono::seconds(30));
    std::size_t relayAddressAttempt = 0;
    int readyFd = readyPipe[1];
    tailgate::crypto::Bytes32 machineKey = identity->MachinePrivateKey;
    tailgate::crypto::Bytes32 nodePrivateKey = identity->NodePrivateKey;
    tailgate::crypto::Bytes32 discoPrivateKey = identity->DiscoPrivateKey;
    std::string pendingAuthKey = identity->RegistrationComplete ? std::string{} : authKey;
    std::string fallbackAuthKey = identity->RegistrationComplete ? authKey : std::string{};
    std::string pendingAuthorizationUrl;
    const auto registrationAccepted = [&]()
    {
        pendingAuthKey.clear();
        fallbackAuthKey.clear();
        pendingAuthorizationUrl.clear();
        status.AuthorizationUrl.clear();
        status.Error.clear();
        const std::optional<tailgate::linux_frontend::IdentityState> current =
            tailgate::linux_frontend::ReadIdentity();
        if (current && !current->RegistrationComplete)
        {
            tailgate::linux_frontend::IdentityState completed = *current;
            completed.RegistrationComplete = true;
            tailgate::linux_frontend::WriteIdentity(completed);
        }
    };
    const auto registrationPending =
        [&](const tailgate::control::client::RegistrationResult& registration)
    {
        const bool loginRequired =
            registration.State == tailgate::control::client::RegistrationState::LoginRequired;
        pendingAuthorizationUrl = loginRequired ? registration.AuthorizationUrl : std::string{};
        status.BackendState = loginRequired ? "NeedsLogin" : "NeedsMachineAuth";
        status.Online = false;
        status.AuthorizationUrl =
            loginRequired ? registration.AuthorizationUrl : registration.ApprovalUrl;
        status.Error.clear();
        tailgate::linux_frontend::WriteDaemonStatus(status);
        tailgate::base::Log(tailgate::base::LogLevel::Info,
                            "control",
                            loginRequired ? std::format("waiting for interactive login code={}",
                                                        registration.AuthorizationCode.empty()
                                                            ? "unavailable"
                                                            : registration.AuthorizationCode)
                                          : std::format("waiting for machine approval url={}",
                                                        registration.ApprovalUrl));
    };
    const auto recordConnectionFailure = [&](const std::exception& error)
    {
        tailgate::linux_frontend::RestoreResolverConfiguration();
        if (status.Online)
        {
            retryBackoff.Reset();
        }
        const std::chrono::milliseconds retryDelay = retryBackoff.NextDelay();
        const auto retrySeconds =
            std::chrono::duration_cast<std::chrono::seconds>(retryDelay).count();
        status.BackendState = "Starting";
        status.Online = false;
        status.Error = error.what();
        tailgate::linux_frontend::WriteDaemonStatus(status);
        tailgate::base::Log(tailgate::base::LogLevel::Error,
                            "daemon",
                            std::format("{}; retrying in {} seconds", error.what(), retrySeconds));
        for (int elapsed = 0; elapsed < retrySeconds && !StopRequested && !ReloadRequested;
             ++elapsed)
        {
            sleep(1);
        }
    };
    while (!StopRequested)
    {
        try
        {
            const auto settings = tailgate::linux_frontend::ReadSettings();
            if (const auto currentIdentity = tailgate::linux_frontend::ReadIdentity())
            {
                machineKey = currentIdentity->MachinePrivateKey;
                nodePrivateKey = currentIdentity->NodePrivateKey;
                discoPrivateKey = currentIdentity->DiscoPrivateKey;
            }
            if (settings && !settings->Hostname.empty())
            {
                host.Hostname = settings->Hostname;
            }
            ReloadRequested = 0;
            tailgate::linux_frontend::RestoreResolverConfiguration();
            const std::string selectedExitNode = settings ? settings->ExitNode : options.ExitNode;
            status.ConfigurationRevision = settings ? settings->Revision : 0;
            status.BackendState = "Starting";
            status.Online = false;
            status.Error.clear();
            tailgate::linux_frontend::WriteDaemonStatus(status);
            tailgate::base::Log(
                tailgate::base::LogLevel::Info,
                "daemon",
                std::format("connecting hostname={} accept-dns={} exit-node={}",
                            host.Hostname,
                            (settings ? settings->AcceptDns : options.AcceptDns) ? "true" : "false",
                            selectedExitNode.empty() ? "none" : selectedExitNode));
            const std::string tailgateUrl = settings ? settings->TailgateUrl : options.TailgateUrl;
            if (!tailgateUrl.empty())
            {
                RunRelayConnection(tailgateUrl,
                                   pendingAuthKey,
                                   pendingAuthorizationUrl,
                                   host,
                                   machineKey,
                                   nodePrivateKey,
                                   discoPrivateKey,
                                   settings ? settings->AcceptDns : options.AcceptDns,
                                   settings ? settings->ExitNode : options.ExitNode,
                                   status,
                                   readyFd,
                                   relayAddressAttempt++,
                                   registrationAccepted,
                                   registrationPending,
                                   fallbackAuthKey);
            }
            else
            {
                RunConnection(pendingAuthKey,
                              host,
                              machineKey,
                              nodePrivateKey,
                              settings ? settings->AcceptDns : options.AcceptDns,
                              settings ? settings->ExitNode : options.ExitNode,
                              settings ? settings->FunnelPort : 0,
                              settings ? settings->FunnelLocalPort : 0,
                              settings ? settings->ExposePort : 0,
                              status,
                              readyFd,
                              -1,
                              nullptr,
                              nullptr,
                              true,
                              true,
                              {},
                              {},
                              {},
                              registrationAccepted,
                              pendingAuthorizationUrl,
                              registrationPending,
                              fallbackAuthKey);
            }
            if (ReloadRequested)
            {
                tailgate::base::Log(tailgate::base::LogLevel::Info,
                                    "daemon",
                                    "settings changed; reconnecting data plane");
            }
            retryBackoff.Reset();
        }
        catch (const std::exception& error)
        {
            recordConnectionFailure(error);
        }
    }

    tailgate::base::Log(tailgate::base::LogLevel::Info, "daemon", "shutdown requested");
    tailgate::linux_frontend::RestoreResolverConfiguration();

    if (readyFd >= 0)
    {
        close(readyFd);
    }
    tailgate::linux_frontend::RemoveResolverBackup();
    tailgate::base::Log(tailgate::base::LogLevel::Info, "daemon", "shutdown complete");
    _exit(0);
}

} // namespace

namespace tailgate::platform
{
namespace
{

class LinuxFrontend final : public IPlatformFrontend
{
public:
    UpResult Up(const cli::UpOptions& options) override
    {
        return RunUp(options);
    }

    int Down() override
    {
        return RunDown();
    }

    int Logout() override
    {
        return RunLogout();
    }

    int Set(const cli::SetOptions& options) override
    {
        const auto existing = RequireRunningDaemon();
        tailgate::linux_frontend::SettingsState settings =
            tailgate::linux_frontend::ReadSettings().value_or(
                tailgate::linux_frontend::SettingsState{});
        const tailgate::linux_frontend::SettingsState previousSettings = settings;
        if (options.Hostname)
        {
            settings.Hostname = *options.Hostname;
        }
        if (options.ExitNode)
        {
            settings.ExitNode = *options.ExitNode;
        }
        if (options.TailgateUrl)
        {
            if (!options.TailgateUrl->empty() && settings.ExposePort != 0)
            {
                throw std::runtime_error(
                    "this node is running expose; stop expose before enabling --tailgate");
            }
            settings.TailgateUrl = *options.TailgateUrl;
        }
        StopRequested = 0;
        std::signal(SIGINT, HandleStopSignal);
        std::signal(SIGTERM, HandleStopSignal);
        tailgate::linux_frontend::WriteSettings(settings);
        ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
        try
        {
            (void)WaitForDaemonReload(static_cast<pid_t>(existing.ProcessId), existing.Error, true);
        }
        catch (...)
        {
            const std::exception_ptr failure = std::current_exception();
            tailgate::linux_frontend::WriteSettings(previousSettings);
            ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
            StopRequested = 0;
            try
            {
                (void)WaitForDaemonReload(static_cast<pid_t>(existing.ProcessId));
            }
            catch (const std::exception& rollbackError)
            {
                tailgate::base::Log(tailgate::base::LogLevel::Error,
                                    "settings",
                                    "failed to restore previous settings: " +
                                        std::string(rollbackError.what()));
            }
            std::rethrow_exception(failure);
        }
        return 0;
    }

    int Funnel(const cli::FunnelOptions& options) override
    {
        tailgate::linux_frontend::DaemonStatus existing = RequireRunningDaemon();
        tailgate::linux_frontend::SettingsState settings =
            tailgate::linux_frontend::ReadSettings().value_or(
                tailgate::linux_frontend::SettingsState{});
        if (options.Off)
        {
            if (settings.FunnelPort == options.Port)
            {
                settings.FunnelPort = 0;
                settings.FunnelLocalPort = 0;
                tailgate::linux_frontend::WriteSettings(settings);
                ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
                WaitForDaemonReload(static_cast<pid_t>(existing.ProcessId), existing.Error);
            }
            std::cout << "Funnel stopped.\n";
            return 0;
        }
        const tailgate::linux_frontend::SettingsState previousSettings = settings;
        settings.FunnelPort = options.Port;
        settings.FunnelLocalPort = options.LocalPort;
        tailgate::linux_frontend::WriteSettings(settings);
        ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
        try
        {
            existing = WaitForDaemonReload(static_cast<pid_t>(existing.ProcessId), existing.Error);
        }
        catch (...)
        {
            const auto failedStatus = tailgate::linux_frontend::ReadDaemonStatus();
            const std::string failedError = failedStatus ? failedStatus->Error : "";
            tailgate::linux_frontend::WriteSettings(previousSettings);
            try
            {
                ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
                (void)WaitForDaemonReload(static_cast<pid_t>(existing.ProcessId), failedError);
            }
            catch (const std::exception& rollbackError)
            {
                tailgate::base::Log(tailgate::base::LogLevel::Error,
                                    "funnel",
                                    "failed to restore previous settings: " +
                                        std::string(rollbackError.what()));
            }
            throw;
        }
        PrintFunnelAvailability(existing, options, options.Background);
        if (options.Background)
        {
            return 0;
        }
        std::signal(SIGINT, HandleStopSignal);
        std::signal(SIGTERM, HandleStopSignal);
        while (!StopRequested)
        {
            pause();
        }
        settings = tailgate::linux_frontend::ReadSettings().value_or(settings);
        if (settings.FunnelPort == options.Port)
        {
            settings.FunnelPort = 0;
            settings.FunnelLocalPort = 0;
            tailgate::linux_frontend::WriteSettings(settings);
            existing = RequireRunningDaemon();
            ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
        }
        return 0;
    }

    int Expose(const cli::ExposeOptions& options) override
    {
        tailgate::linux_frontend::DaemonStatus existing = RequireRunningDaemon();
        tailgate::linux_frontend::SettingsState settings =
            tailgate::linux_frontend::ReadSettings().value_or(
                tailgate::linux_frontend::SettingsState{});
        if (options.Off)
        {
            if (settings.ExposePort == options.Port)
            {
                settings.ExposePort = 0;
                settings.FunnelPort = 0;
                settings.FunnelLocalPort = 0;
                tailgate::linux_frontend::WriteSettings(settings);
                ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
                (void)WaitForDaemonReload(static_cast<pid_t>(existing.ProcessId), existing.Error);
            }
            std::cout << "Tailgate expose stopped.\n";
            return 0;
        }

        const tailgate::linux_frontend::SettingsState previousSettings = settings;
        settings.ExposePort = options.Port;
        settings.FunnelPort = options.Port;
        settings.FunnelLocalPort = ExposeLocalPort;
        tailgate::linux_frontend::WriteSettings(settings);
        ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
        try
        {
            existing = WaitForDaemonReload(static_cast<pid_t>(existing.ProcessId), existing.Error);
        }
        catch (...)
        {
            tailgate::linux_frontend::WriteSettings(previousSettings);
            ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
            throw;
        }
        const std::string url =
            std::format("https://{}.{}:{}", existing.Hostname, existing.Domain, options.Port);
        std::cout << std::format("Exposed to the internet at: {}\n\n", url);
        if (options.Background)
        {
            std::cout << "Tailgate opened and running in the background.\n";
            std::cout << std::format("To disable the proxy, run: tailgate expose --port={} off\n",
                                     options.Port);
            return 0;
        }
        std::cout << "Press Ctrl+C to exit.\n";
        std::signal(SIGINT, HandleStopSignal);
        std::signal(SIGTERM, HandleStopSignal);
        while (!StopRequested)
        {
            pause();
        }
        settings = tailgate::linux_frontend::ReadSettings().value_or(settings);
        if (settings.ExposePort == options.Port)
        {
            settings.ExposePort = 0;
            settings.FunnelPort = 0;
            settings.FunnelLocalPort = 0;
            tailgate::linux_frontend::WriteSettings(settings);
            existing = RequireRunningDaemon();
            ReloadDaemon(static_cast<pid_t>(existing.ProcessId));
        }
        return 0;
    }

    tailgate::Status ReadStatus() override
    {
        std::optional<tailgate::linux_frontend::DaemonStatus> status =
            tailgate::linux_frontend::ReadDaemonStatus();
        if (!status)
        {
            return {};
        }
        if (!tailgate::linux_frontend::IsProcessRunning(status->ProcessId))
        {
            status->Online = false;
            status->BackendState = "Stopped";
            tailgate::linux_frontend::RestoreResolverConfiguration();
        }
        return *status;
    }

    PingResult PingOnce(const std::string& target,
                        int timeoutSeconds,
                        std::uint16_t sequence,
                        bool tsmp) override
    {
        (void)sequence;
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        addrinfo* addresses = nullptr;
        const int result = getaddrinfo(target.c_str(), nullptr, &hints, &addresses);
        if (result != 0)
        {
            throw std::runtime_error(
                std::format("cannot resolve {}: {}", target, gai_strerror(result)));
        }
        std::string resolved;
        for (addrinfo* current = addresses; current != nullptr; current = current->ai_next)
        {
            const auto* address = reinterpret_cast<const sockaddr_in*>(current->ai_addr);
            std::vector<char> text(INET_ADDRSTRLEN);
            if (inet_ntop(AF_INET,
                          &address->sin_addr,
                          text.data(),
                          static_cast<socklen_t>(text.size())) != nullptr)
            {
                resolved = text.data();
                break;
            }
        }
        freeaddrinfo(addresses);
        if (resolved.empty())
        {
            throw std::runtime_error("cannot resolve " + target + " to an IPv4 address");
        }
        const tailgate::Status status = ReadStatus();
        if (!status.Address.empty() && resolved == status.Address)
        {
            PingResult local;
            local.Local = true;
            local.NodeName = status.Hostname;
            local.NodeAddress = status.Address;
            return local;
        }
        return tailgate::linux_frontend::RequestDaemonPing(resolved, timeoutSeconds, tsmp);
    }
};

} // namespace

std::unique_ptr<IPlatformFrontend> CreateFrontend()
{
    namespace di = boost::di;
    auto injector = di::make_injector(tailgate::di::Bindings(),
                                      di::bind<IPlatformFrontend>.to<LinuxFrontend>());
    return injector.create<std::unique_ptr<IPlatformFrontend>>();
}

} // namespace tailgate::platform
