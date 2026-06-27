#include "LinuxDataplaneEvents.h"
#include "LinuxDerpWorker.h"
#include "LinuxFiles.h"
#include "LinuxHost.h"
#include "LinuxNetwork.h"
#include "LinuxPingIpc.h"
#include "LinuxState.h"
#include "LinuxStatusWriter.h"
#include "TcpStream.h"
#include "UniqueFd.h"
#include "tailgate/Logging.h"
#include "tailgate/PlatformFrontend.h"

#include "tailgate/cli/Arguments.h"
#include "tailgate/control/ControlClient.h"
#include "tailgate/network/Dns.h"
#include "tailgate/network/Ipv4.h"
#include "tailgate/protocol/ControlHandshake.h"
#include "tailgate/protocol/Crypto.h"
#include "tailgate/protocol/DerpClient.h"
#include "tailgate/protocol/Disco.h"
#include "tailgate/protocol/WireGuardTunnel.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <ctime>
#include <deque>
#include <exception>
#include <fcntl.h>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <arpa/inet.h>
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
#include <unistd.h>

namespace
{

volatile std::sig_atomic_t StopRequested = 0;
volatile std::sig_atomic_t ReloadRequested = 0;

void HandleStopSignal(int)
{
    StopRequested = 1;
}

void HandleReloadSignal(int)
{
    ReloadRequested = 1;
}

using tailgate::linux_frontend::AddEpollInterest;
using tailgate::linux_frontend::AddRoute;
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
using tailgate::linux_frontend::SendUdp;
using tailgate::linux_frontend::SetInterfaceAddress;
using tailgate::linux_frontend::SetInterfaceMtu;
using tailgate::linux_frontend::SocketPort;
using tailgate::linux_frontend::TrySendUdp;
using tailgate::linux_frontend::UniqueFd;
using tailgate::linux_frontend::UnpackDataplaneEvent;
using tailgate::linux_frontend::WriteAll;
using tailgate::linux_frontend::WriteResolver;
using Ipv4Prefix = tailgate::network::Ipv4Prefix;
using TailPeer = tailgate::control::PeerConfig;

struct PeerRuntime
{
    TailPeer Config;
    tailgate::protocol::WireGuardTunnel::PeerId TunnelPeer = 0;
    UniqueFd Socket;
    sockaddr_in Endpoint{};
    bool HasEndpoint = false;
    bool DirectProbeStarted = false;
    bool AwaitingDirectResponse = false;
    tailgate::protocol::Disco::TransactionId DirectProbeTransaction{};
    std::chrono::steady_clock::time_point FirstUnansweredDirectSend{};
    std::chrono::steady_clock::time_point LastDirectProbe{};
    tailgate::protocol::WireGuardTunnel::Key PublicKey{};
    tailgate::protocol::Bytes32 DiscoPublicKey{};
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
constexpr auto HandshakeRetryInterval = std::chrono::seconds(5);
constexpr auto DirectProbeInterval = std::chrono::seconds(5);
constexpr auto DataplaneSlowSection = std::chrono::milliseconds(50);
constexpr auto PendingDnsTimeout = std::chrono::seconds(10);
constexpr auto PingRetryInterval = std::chrono::seconds(1);
constexpr int TailgateMtu = 1280;

template <typename Callback>
void TimedSection(const char* name, Callback&& callback)
{
    const auto started = std::chrono::steady_clock::now();
    callback();
    const auto elapsed = std::chrono::steady_clock::now() - started;
    if (elapsed >= DataplaneSlowSection)
    {
        tailgate::Log(
            tailgate::LogLevel::Warning,
            "dataplane",
            std::string(name) + " took " +
                std::to_string(
                    std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count()) +
                "ms");
    }
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

bool HasOnlineExitNode(const tailgate::linux_frontend::DaemonStatus& status,
                       const std::string& nameOrAddress)
{
    return std::any_of(status.Peers.begin(),
                       status.Peers.end(),
                       [&](const tailgate::linux_frontend::PeerStatus& peer)
                       {
                           return peer.ExitNodeOption && peer.Online &&
                                  (peer.Address == nameOrAddress ||
                                   peer.Hostname == DisplayName(nameOrAddress));
                       });
}

std::uint32_t Ipv4ToHostOrder(const std::string& ip)
{
    const auto address = tailgate::network::ParseIpv4(ip);
    if (!address)
    {
        throw std::runtime_error("invalid IPv4 address: " + ip);
    }
    return *address;
}

void StartTunnel(const tailgate::protocol::Bytes32& nodePrivateKey,
                 const tailgate::protocol::Bytes32& nodePublicKey,
                 const tailgate::protocol::Bytes32& discoPrivateKey,
                 const std::string& selfIp,
                 const std::string& initialDnsResolver,
                 const std::vector<std::string>& initialDnsDomains,
                 const std::vector<std::string>& initialDnsDefaultResolvers,
                 const std::vector<tailgate::control::NetworkConfig::DnsRoute>& initialDnsRoutes,
                 const std::vector<TailPeer>& peerConfigs,
                 int derpRegion,
                 const std::string& derpHost,
                 const std::string& exitNode,
                 bool acceptDns,
                 tailgate::control::ControlClient* control,
                 int controlFd,
                 tailgate::linux_frontend::DaemonStatus& status,
                 int& readyFd)
{
    std::string interfaceName = "tailgate0";
    const std::string underlayInterface = DefaultRouteInterface();
    const std::uint32_t underlayAddress = InterfaceIpv4Address(underlayInterface);
    const std::vector<std::string> originalResolvers = ReadResolverAddresses();
    std::string currentDnsResolver = initialDnsResolver;
    std::vector<std::string> currentDnsDomains = initialDnsDomains;
    std::vector<std::string> currentDnsDefaultResolvers = initialDnsDefaultResolvers;
    std::vector<tailgate::control::NetworkConfig::DnsRoute> currentDnsRoutes = initialDnsRoutes;

    UniqueFd tun = OpenTun(interfaceName);
    UniqueFd localDns;
    if (acceptDns)
    {
        localDns = OpenLocalDnsSocket();
    }
    SetInterfaceAddress(interfaceName, selfIp);
    SetInterfaceMtu(interfaceName, TailgateMtu);
    AddRoute(interfaceName, Ipv4Prefix{Ipv4ToHostOrder("100.64.0.0"), 10});
    AddRoute(interfaceName, Ipv4Prefix{Ipv4ToHostOrder(currentDnsResolver), 32});

    tailgate::protocol::WireGuardTunnel tunnel(nodePrivateKey);
    tailgate::protocol::Disco disco(discoPrivateKey, nodePublicKey);

    std::deque<PeerRuntime> peers;
    auto buildPeerRuntime = [&](const TailPeer& config) -> std::optional<PeerRuntime>
    {
        std::vector<std::uint8_t> publicKeyBytes =
            tailgate::protocol::HexToBytes(config.Key.substr(8));
        if (publicKeyBytes.size() != tailgate::protocol::WireGuardTunnel::Key{}.size())
        {
            return std::nullopt;
        }
        tailgate::protocol::WireGuardTunnel::Key publicKey{};
        std::copy(publicKeyBytes.begin(), publicKeyBytes.end(), publicKey.begin());
        PeerRuntime runtime;
        runtime.Config = config;
        runtime.TunnelPeer = tunnel.AddPeer(publicKey);
        runtime.PublicKey = publicKey;
        if (config.DiscoKey.rfind("discokey:", 0) == 0)
        {
            const auto discoKey = tailgate::protocol::HexToBytes(config.DiscoKey.substr(9));
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
        tailgate::Log(tailgate::LogLevel::Info,
                      "derp",
                      "connecting region=" + std::to_string(region) + " host=" + host +
                          (preferred ? " preferred" : ""));
        derps.push_back({region,
                         host,
                         std::make_unique<DerpWorker>(
                             host, underlayInterface, nodePrivateKey, nodePublicKey, preferred)});
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
    if (acceptDns)
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
    auto sendRelay = [&](const PeerRuntime& peer, const std::vector<std::uint8_t>& packet)
    {
        derpForPeer(peer).Send(peer.PublicKey, packet);
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
        exitPeerIndex = tailgate::control::FindExitNode(routablePeers, exitNode, true);
        if (!exitPeerIndex)
        {
            throw std::runtime_error("exit node was not found in the network map: " + exitNode);
        }
        exitPeer = &peers[*exitPeerIndex];
        AddRoute(interfaceName, Ipv4Prefix{Ipv4ToHostOrder("0.0.0.0"), 1});
        AddRoute(interfaceName, Ipv4Prefix{Ipv4ToHostOrder("128.0.0.0"), 1});
        tailgate::Log(tailgate::LogLevel::Info,
                      "tunnel",
                      "exit node=" + exitPeer->Config.Name +
                          " address=" + exitPeer->Config.Address);
    }

    auto findRoute = [&](std::uint32_t destination) -> PeerRuntime*
    {
        const auto index = tailgate::control::FindRoute(routablePeers, destination, exitPeerIndex);
        return index ? &peers[*index] : nullptr;
    };

    auto peerForKey = [&](const tailgate::protocol::DerpClient::Key& key) -> PeerRuntime*
    {
        auto found = std::find_if(peers.begin(),
                                  peers.end(),
                                  [&](const PeerRuntime& peer)
                                  {
                                      return peer.PublicKey == key;
                                  });
        return found == peers.end() ? nullptr : &*found;
    };
    auto peerForDiscoKey = [&](const tailgate::protocol::Bytes32& key) -> PeerRuntime*
    {
        auto found = std::find_if(peers.begin(),
                                  peers.end(),
                                  [&](const PeerRuntime& peer)
                                  {
                                      return peer.HasDiscoKey && peer.DiscoPublicKey == key;
                                  });
        return found == peers.end() ? nullptr : &*found;
    };

    auto startDirectProbe = [&](PeerRuntime& peer)
    {
        if (!peer.HasDiscoKey || peer.HasEndpoint)
        {
            return;
        }
        const auto now = std::chrono::steady_clock::now();
        if (peer.LastDirectProbe != std::chrono::steady_clock::time_point{} &&
            now - peer.LastDirectProbe < DirectProbeInterval)
        {
            return;
        }
        peer.DirectProbeStarted = true;
        peer.LastDirectProbe = now;
        peer.DirectProbeTransaction = disco.NewTransactionId();
        sendRelay(peer,
                  disco.BuildCallMeMaybe(peer.DiscoPublicKey,
                                         {{underlayAddress, SocketPort(peer.Socket.Fd)}}));
        const std::vector<std::uint8_t> ping =
            disco.BuildPing(peer.DiscoPublicKey, peer.DirectProbeTransaction);
        const std::vector<std::uint8_t> handshake = tunnel.CreateHandshake(peer.TunnelPeer);
        for (const std::string& endpoint : peer.Config.Endpoints)
        {
            const sockaddr_in candidate = ParseIpv4Endpoint(endpoint);
            SendUdp(peer.Socket.Fd, candidate, ping);
            SendUdp(peer.Socket.Fd, candidate, handshake);
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
            tailgate::Log(tailgate::LogLevel::Debug,
                          "tunnel",
                          "UDP backpressure peer=" + peer.Config.Name +
                              " queued=" + std::to_string(peer.OutgoingPackets.size()) +
                              " bytes=" + std::to_string(peer.OutgoingBytes) +
                              " events=" + std::to_string(peer.UdpBackpressureEvents));
        }
        while (!peer.OutgoingPackets.empty() &&
               (peer.OutgoingPackets.size() >= MaximumPendingPacketsPerPeer ||
                peer.OutgoingBytes + packet.size() > MaximumPendingBytesPerPeer))
        {
            peer.OutgoingBytes -= peer.OutgoingPackets.front().size();
            peer.OutgoingPackets.pop_front();
            tailgate::Log(tailgate::LogLevel::Warning,
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
        while (peer.HasEndpoint && !peer.OutgoingPackets.empty())
        {
            if (!TrySendUdp(peer.Socket.Fd, peer.Endpoint, peer.OutgoingPackets.front()))
            {
                return;
            }
            peer.OutgoingBytes -= peer.OutgoingPackets.front().size();
            peer.OutgoingPackets.pop_front();
        }
    };
    auto sendPeer =
        [&sendRelay, &queueOutgoing, &flushOutgoing](
            PeerRuntime& peer, const std::vector<std::uint8_t>& packet, bool expectResponse = true)
    {
        peer.TxBytes += packet.size();
        if (peer.HasEndpoint)
        {
            flushOutgoing(peer);
            if (peer.OutgoingPackets.empty())
            {
                if (!TrySendUdp(peer.Socket.Fd, peer.Endpoint, packet))
                {
                    queueOutgoing(peer, packet);
                }
            }
            else
            {
                queueOutgoing(peer, packet);
            }
            if (expectResponse && !peer.AwaitingDirectResponse)
            {
                peer.AwaitingDirectResponse = true;
                peer.FirstUnansweredDirectSend = std::chrono::steady_clock::now();
            }
        }
        else
        {
            sendRelay(peer, packet);
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
        const std::vector<std::uint8_t> handshake = tunnel.CreateHandshake(peer.TunnelPeer);
        peer.LastHandshake = now;
        tailgate::Log(tailgate::LogLevel::Debug, "tunnel", "handshake peer=" + peer.Config.Name);
        if (peer.HasEndpoint)
        {
            SendUdp(peer.Socket.Fd, peer.Endpoint, handshake);
        }
        else
        {
            sendRelay(peer, handshake);
        }
    };

    PeerRuntime* dnsPeer = findRoute(Ipv4ToHostOrder(currentDnsResolver));
    if (dnsPeer == nullptr)
    {
        throw std::runtime_error("netmap does not contain a route to the DNS resolver");
    }
    sendHandshake(*dnsPeer);
    if (exitPeer != nullptr && exitPeer != dnsPeer)
    {
        sendHandshake(*exitPeer);
    }
    tailgate::Log(tailgate::LogLevel::Info,
                  "tunnel",
                  "ready interface=" + interfaceName + " address=" + selfIp +
                      " dns=" + currentDnsResolver + " peers=" + std::to_string(peers.size()));

    status.BackendState = "Running";
    status.Online = true;
    status.Address = selfIp;
    status.Error.clear();
    status.Peers.clear();
    for (const TailPeer& peer : peerConfigs)
    {
        tailgate::linux_frontend::PeerStatus peerStatus;
        peerStatus.Address = peer.Address;
        peerStatus.Hostname = DisplayName(peer.Name);
        peerStatus.OperatingSystem = peer.OperatingSystem;
        peerStatus.Relay =
            peer.DerpCode.empty() ? "derp-" + std::to_string(peer.DerpRegion) : peer.DerpCode;
        peerStatus.Online = peer.Online;
        peerStatus.ExitNodeOption = peer.ExitNodeOption;
        status.Peers.push_back(std::move(peerStatus));
    }
    tailgate::linux_frontend::WriteDaemonStatus(status);
    tailgate::linux_frontend::LinuxStatusWriter statusWriter;
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
            tailgate::Log(
                tailgate::LogLevel::Warning, "tunnel", "outbound TUN queue limit reached");
        }
        if (packet.size() <= MaximumPendingBytesPerPeer)
        {
            pendingTunBytes += packet.size();
            pendingTunPackets.push_back(std::move(packet));
            flushTun();
        }
    };
    UniqueFd upstreamDns = OpenUdpSocket(underlayInterface);
    UniqueFd pingServer = tailgate::linux_frontend::OpenPingServer();
    struct PendingPing
    {
        tailgate::protocol::Disco::TransactionId Transaction{};
        PeerRuntime* Peer = nullptr;
        sockaddr_un Client{};
        socklen_t ClientLength = 0;
        std::chrono::steady_clock::time_point Started{};
        std::chrono::steady_clock::time_point LastSent{};
        int TimeoutSeconds = 0;
    };
    std::vector<PendingPing> pendingPings;
    auto nextPeriodicStatus = std::chrono::steady_clock::now() + StatusRefreshInterval;
    struct ControlUpdateWorker
    {
        tailgate::control::ControlClient* Control = nullptr;
        int ControlFd = -1;
        UniqueFd Event;
        std::mutex Mutex;
        std::deque<tailgate::control::NetworkConfig> Updates;
        std::exception_ptr Error;
        std::atomic_bool Stop = false;
        std::thread Thread;

        ControlUpdateWorker(tailgate::control::ControlClient* controlClient, int fd)
            : Control(controlClient), ControlFd(fd), Event(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK))
        {
            if (Control == nullptr || ControlFd < 0)
            {
                Event.Reset();
                return;
            }
            if (Event.Fd < 0)
            {
                throw std::runtime_error("eventfd failed: " + std::string(std::strerror(errno)));
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
            if (ControlFd >= 0)
            {
                shutdown(ControlFd, SHUT_RDWR);
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
            try
            {
                pollfd descriptor{};
                descriptor.fd = ControlFd;
                descriptor.events = POLLIN | POLLERR | POLLHUP;
                while (!Stop)
                {
                    descriptor.revents = 0;
                    const int ready = poll(&descriptor, 1, -1);
                    if (ready < 0 && errno == EINTR)
                    {
                        continue;
                    }
                    if (ready < 0)
                    {
                        throw std::runtime_error("control poll failed: " +
                                                 std::string(std::strerror(errno)));
                    }
                    if ((descriptor.revents & (POLLERR | POLLHUP)) != 0)
                    {
                        throw std::runtime_error("control stream closed");
                    }
                    if ((descriptor.revents & POLLIN) == 0)
                    {
                        continue;
                    }
                    bool changed = false;
                    while (std::optional<tailgate::control::NetworkConfig> update =
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
            catch (...)
            {
                if (!Stop)
                {
                    std::lock_guard<std::mutex> lock(Mutex);
                    Error = std::current_exception();
                    Wake();
                }
            }
        }

        std::deque<tailgate::control::NetworkConfig> TakeUpdates()
        {
            std::lock_guard<std::mutex> lock(Mutex);
            if (Error)
            {
                std::rethrow_exception(Error);
            }
            std::deque<tailgate::control::NetworkConfig> result;
            result.swap(Updates);
            return result;
        }
    };

    auto queueOrSend = [&](PeerRuntime& peer, std::vector<std::uint8_t> plaintext)
    {
        if (tunnel.HasSession(peer.TunnelPeer))
        {
            sendPeer(peer, tunnel.Encrypt(peer.TunnelPeer, plaintext));
            return;
        }
        while (!peer.PendingPackets.empty() &&
               (peer.PendingPackets.size() >= MaximumPendingPacketsPerPeer ||
                peer.PendingBytes + plaintext.size() > MaximumPendingBytesPerPeer))
        {
            peer.PendingBytes -= peer.PendingPackets.front().size();
            peer.PendingPackets.pop_front();
            tailgate::Log(tailgate::LogLevel::Warning,
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
        while (tunnel.HasSession(peer.TunnelPeer) && !peer.PendingPackets.empty())
        {
            std::vector<std::uint8_t> plaintext = std::move(peer.PendingPackets.front());
            peer.PendingPackets.pop_front();
            peer.PendingBytes -= plaintext.size();
            sendPeer(peer, tunnel.Encrypt(peer.TunnelPeer, plaintext));
        }
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
            const std::optional<std::uint32_t> destination =
                tailgate::network::Ipv4Destination(packet);
            if (!destination)
            {
                continue;
            }
            PeerRuntime* peer = findRoute(*destination);
            if (!peer)
            {
                tailgate::Log(tailgate::LogLevel::Warning,
                              "tunnel",
                              "dropping unroutable packet to " +
                                  tailgate::network::FormatIpv4(*destination));
                continue;
            }
            queueOrSend(*peer, std::move(packet));
        }
    };
    auto selectDnsResolver = [&](const std::vector<std::uint8_t>& query)
    {
        const auto name = tailgate::network::DnsQueryName(query);
        const std::vector<std::string>* selected = nullptr;
        std::size_t selectedSuffixLength = 0;
        for (const auto& route : currentDnsRoutes)
        {
            if (name && route.Suffix.size() >= selectedSuffixLength &&
                tailgate::network::DnsNameHasSuffix(*name, route.Suffix))
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
        if (!tailgate::network::ParseIpv4(resolver))
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
            auto payload = tailgate::network::ExtractUdpPayload(
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

    auto copyText = [](char* output, std::size_t capacity, const std::string& value)
    {
        std::copy_n(value.data(), std::min(value.size(), capacity - 1), output);
    };
    auto completePing = [&](PendingPing& pending, bool responded, const std::string& endpoint)
    {
        tailgate::linux_frontend::PingResponse response{};
        response.Responded = responded ? 1 : 0;
        response.LatencyMilliseconds =
            static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::steady_clock::now() - pending.Started)
                                 .count());
        copyText(response.NodeName, sizeof(response.NodeName), pending.Peer->Config.Name);
        copyText(response.NodeAddress, sizeof(response.NodeAddress), pending.Peer->Config.Address);
        copyText(response.Endpoint, sizeof(response.Endpoint), endpoint);
        copyText(response.Relay,
                 sizeof(response.Relay),
                 pending.Peer->Config.DerpCode.empty()
                     ? "derp-" + std::to_string(pending.Peer->Config.DerpRegion)
                     : pending.Peer->Config.DerpCode);
        tailgate::linux_frontend::SendPingResponse(
            pingServer.Fd, pending.Client, pending.ClientLength, response);
        pending.Peer = nullptr;
    };
    auto sendPendingPing = [&](PendingPing& pending)
    {
        if (pending.Peer == nullptr)
        {
            return;
        }
        const auto ping = disco.BuildPing(pending.Peer->DiscoPublicKey, pending.Transaction);
        sendRelay(*pending.Peer, ping);
        for (const std::string& endpoint : pending.Peer->Config.Endpoints)
        {
            SendUdp(pending.Peer->Socket.Fd, ParseIpv4Endpoint(endpoint), ping);
        }
        pending.LastSent = std::chrono::steady_clock::now();
    };
    auto relayName = [](const TailPeer& peer)
    {
        return peer.DerpCode.empty() ? "derp-" + std::to_string(peer.DerpRegion) : peer.DerpCode;
    };
    auto updateRuntimeDiscoKey = [](PeerRuntime& peer)
    {
        peer.HasDiscoKey = false;
        peer.DiscoPublicKey = {};
        if (peer.Config.DiscoKey.rfind("discokey:", 0) != 0)
        {
            return;
        }
        const auto discoKey = tailgate::protocol::HexToBytes(peer.Config.DiscoKey.substr(9));
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
            std::string(inet_ntoa(source.sin_addr)) + ":" + std::to_string(ntohs(source.sin_port));
        const bool changed = !peer.HasEndpoint ||
                             peer.Endpoint.sin_addr.s_addr != source.sin_addr.s_addr ||
                             peer.Endpoint.sin_port != source.sin_port;
        peer.Endpoint = source;
        peer.HasEndpoint = true;
        peer.AwaitingDirectResponse = false;
        if (changed)
        {
            tailgate::Log(tailgate::LogLevel::Info,
                          component,
                          "direct peer=" + peer.Config.Name + " endpoint=" + endpoint);
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
                    statusWriter.Submit(status);
                }
            }
        }
    };
    auto handleDisco = [&](PeerRuntime& peer,
                           const std::vector<std::uint8_t>& packet,
                           const std::optional<sockaddr_in>& source,
                           DerpWorker* sourceDerp,
                           const tailgate::protocol::DerpClient::Key* derpSource)
    {
        const auto message = disco.Parse(packet);
        if (!message || message->Sender != peer.DiscoPublicKey)
        {
            return;
        }
        if (message->Type == tailgate::protocol::Disco::MessageType::CallMeMaybe)
        {
            if (derpSource == nullptr)
            {
                return;
            }
            const auto transaction = disco.NewTransactionId();
            const auto ping = disco.BuildPing(peer.DiscoPublicKey, transaction);
            for (const auto& candidate : message->Endpoints)
            {
                sockaddr_in endpoint{};
                endpoint.sin_family = AF_INET;
                endpoint.sin_addr.s_addr = htonl(candidate.Address);
                endpoint.sin_port = htons(candidate.Port);
                SendUdp(peer.Socket.Fd, endpoint, ping);
            }
            peer.DirectProbeStarted = true;
            tailgate::Log(tailgate::LogLevel::Debug,
                          "disco",
                          "CallMeMaybe peer=" + peer.Config.Name +
                              " endpoints=" + std::to_string(message->Endpoints.size()));
            return;
        }
        if (message->Type == tailgate::protocol::Disco::MessageType::Ping)
        {
            const std::uint32_t sourceAddress = source ? ntohl(source->sin_addr.s_addr) : 0;
            const std::uint16_t sourcePort = source ? ntohs(source->sin_port) : 0;
            const auto pong = disco.BuildPong(
                peer.DiscoPublicKey, message->Transaction, sourceAddress, sourcePort);
            if (source)
            {
                markDirect(peer, *source, "disco");
                SendUdp(peer.Socket.Fd, *source, pong);
            }
            else if (derpSource != nullptr)
            {
                if (sourceDerp != nullptr)
                {
                    sourceDerp->Send(*derpSource, pong);
                }
            }
            return;
        }
        if (message->Type == tailgate::protocol::Disco::MessageType::Pong && source)
        {
            markDirect(peer, *source, "disco");
        }
        for (PendingPing& pending : pendingPings)
        {
            if (pending.Peer == &peer && pending.Transaction == message->Transaction)
            {
                std::string endpoint;
                if (source)
                {
                    endpoint = std::string(inet_ntoa(source->sin_addr)) + ":" +
                               std::to_string(ntohs(source->sin_port));
                    peer.Endpoint = *source;
                    peer.HasEndpoint = true;
                }
                completePing(pending, true, endpoint);
                break;
            }
        }
    };
    ControlUpdateWorker controlUpdates(control, controlFd);
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
    AddEpollInterest(
        epollFd.Fd, pingServer.Fd, EPOLLIN, PackDataplaneEvent(DataplaneEventKind::Ping));
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

    auto applyStatusFromNetworkMap = [&](const tailgate::control::NetworkConfig& config)
    {
        bool changed = false;
        for (const TailPeer& peer : config.Peers)
        {
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
            statusWriter.Submit(status);
        }
    };

    auto applyNetworkMap = [&](const tailgate::control::NetworkConfig& config)
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
                        tailgate::Log(tailgate::LogLevel::Info,
                                      "control",
                                      "added peer from network-map update: " + configPeer.Name);
                        continue;
                    }

                    if (existing->Config.Key != configPeer.Key)
                    {
                        const std::vector<std::uint8_t> publicKeyBytes =
                            tailgate::protocol::HexToBytes(configPeer.Key.substr(8));
                        if (publicKeyBytes.size() == existing->PublicKey.size())
                        {
                            std::copy(publicKeyBytes.begin(),
                                      publicKeyBytes.end(),
                                      existing->PublicKey.begin());
                            existing->TunnelPeer = tunnel.AddPeer(existing->PublicKey);
                            existing->HasEndpoint = false;
                            existing->DirectProbeStarted = false;
                            existing->AwaitingDirectResponse = false;
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
                        tailgate::Log(
                            tailgate::LogLevel::Info,
                            "control",
                            "peer update name=" + configPeer.Name +
                                " online=" + std::to_string(configPeer.Online ? 1 : 0) +
                                " disco=" + std::to_string(existing->HasDiscoKey ? 1 : 0) +
                                " endpoints=" + std::to_string(configPeer.Endpoints.size()));
                    }
                    if (!configPeer.Online || endpointsChanged)
                    {
                        existing->HasEndpoint = false;
                        existing->DirectProbeStarted = false;
                        existing->AwaitingDirectResponse = false;
                    }
                }
            });

        TimedSection(
            "control route apply",
            [&]()
            {
                TimedSection("control peer pruning",
                             [&]()
                             {
                                 for (PeerRuntime& peer : peers)
                                 {
                                     const bool stillPresent = std::any_of(
                                         config.Peers.begin(),
                                         config.Peers.end(),
                                         [&](const TailPeer& configPeer)
                                         {
                                             return (configPeer.NodeId != 0 &&
                                                     peer.Config.NodeId == configPeer.NodeId) ||
                                                    peer.Config.Address == configPeer.Address;
                                         });
                                     if (!stillPresent)
                                     {
                                         peer.Config.Online = false;
                                         peer.Config.AllowedPrefixes.clear();
                                         peer.Config.ExitNodeOption = false;
                                         peer.HasEndpoint = false;
                                         peer.DirectProbeStarted = false;
                                         peer.AwaitingDirectResponse = false;
                                     }
                                 }
                             });

                TimedSection("control DNS config apply",
                             [&]()
                             {
                                 const bool resolverChanged =
                                     currentDnsResolver != config.DnsResolver;
                                 const bool domainsChanged = currentDnsDomains != config.DnsDomains;
                                 if (resolverChanged)
                                 {
                                     currentDnsResolver = config.DnsResolver;
                                     AddRoute(interfaceName,
                                              Ipv4Prefix{Ipv4ToHostOrder(currentDnsResolver), 32});
                                 }
                                 currentDnsDomains = config.DnsDomains;
                                 currentDnsDefaultResolvers = config.DnsDefaultResolvers;
                                 currentDnsRoutes = config.DnsRoutes;
                                 if (acceptDns && (resolverChanged || domainsChanged))
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
                                     exitPeerIndex = tailgate::control::FindExitNode(
                                         routablePeers, exitNode, true);
                                     exitPeer = exitPeerIndex ? &peers[*exitPeerIndex] : nullptr;
                                 }
                                 dnsPeer = findRoute(Ipv4ToHostOrder(currentDnsResolver));
                             });
                TimedSection("control handshake refresh",
                             [&]()
                             {
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
        tailgate::Log(tailgate::LogLevel::Info,
                      "control",
                      "applied live network-map update: peers=" +
                          std::to_string(config.Peers.size()));
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
            case DataplaneEventKind::Maintenance:
                maintenanceExpired = maintenanceExpired || ((event.events & EPOLLIN) != 0);
                break;
            case DataplaneEventKind::Control:
                controlInput = controlInput || ((event.events & EPOLLIN) != 0);
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
            std::deque<tailgate::control::NetworkConfig> updates = controlUpdates.TakeUpdates();
            for (const tailgate::control::NetworkConfig& update : updates)
            {
                applyNetworkMap(update);
            }
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
                        pendingDnsClients.push_back(PendingDns{client,
                                                               resolverAddress,
                                                               dnsId,
                                                               sourcePort,
                                                               std::chrono::steady_clock::now()});
                        PeerRuntime* peer = findRoute(resolverAddress);
                        if (peer)
                        {
                            std::vector<std::uint8_t> dnsPacket =
                                tailgate::network::BuildUdpPacket(Ipv4ToHostOrder(selfIp),
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
            TimedSection(
                "ping IPC",
                [&]()
                {
                    tailgate::linux_frontend::PingRequest request{};
                    sockaddr_un client{};
                    socklen_t clientLength = sizeof(client);
                    if (tailgate::linux_frontend::ReceivePingRequest(
                            pingServer.Fd, request, client, clientLength))
                    {
                        const std::string target(request.Target,
                                                 strnlen(request.Target, sizeof(request.Target)));
                        const std::string normalizedTarget =
                            !target.empty() && target.back() == '.'
                                ? target.substr(0, target.size() - 1)
                                : target;
                        const auto found =
                            std::find_if(peers.begin(),
                                         peers.end(),
                                         [&](const PeerRuntime& peer)
                                         {
                                             std::string name = peer.Config.Name;
                                             if (!name.empty() && name.back() == '.')
                                                 name.pop_back();
                                             const std::size_t dot = name.find('.');
                                             return peer.Config.Address == normalizedTarget ||
                                                    name == normalizedTarget ||
                                                    name.substr(0, dot) == normalizedTarget;
                                         });
                        if (found == peers.end() || !found->HasDiscoKey)
                        {
                            tailgate::Log(tailgate::LogLevel::Warning,
                                          "ping",
                                          found == peers.end()
                                              ? "target not found: " + normalizedTarget
                                              : "target has no disco key: " + found->Config.Name +
                                                    " online=" +
                                                    std::to_string(found->Config.Online ? 1 : 0));
                            tailgate::linux_frontend::PingResponse response{};
                            tailgate::linux_frontend::SendPingResponse(
                                pingServer.Fd, client, clientLength, response);
                        }
                        else
                        {
                            PendingPing pending;
                            pending.Transaction = disco.NewTransactionId();
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
                        if (tailgate::protocol::Disco::IsDiscoPacket(data))
                        {
                            handleDisco(peer, data, source, nullptr, nullptr);
                            continue;
                        }
                        auto received = tunnel.ProcessPacket(peer.TunnelPeer, data);
                        if (received && !received->Reply.empty())
                        {
                            SendUdp(peer.Socket.Fd, source, received->Reply);
                        }
                        if (received)
                        {
                            peer.AwaitingDirectResponse = false;
                        }
                        std::vector<std::uint8_t> plain =
                            received ? std::move(received->Plaintext) : std::vector<std::uint8_t>{};
                        if (received && received->SessionEstablished)
                        {
                            tailgate::Log(tailgate::LogLevel::Debug,
                                          "tunnel",
                                          "session established peer=" + peer.Config.Name);
                            markDirect(peer, source, "tunnel");
                            flushPending(peer);
                            continue;
                        }
                        if (!plain.empty())
                        {
                            if (handleDnsResponse(plain))
                            {
                                continue;
                            }
                            markDirect(peer, source, "tunnel");
                            queueTun(std::move(plain));
                        }
                    }
                }
            });

        TimedSection("DERP notify",
                     [&]()
                     {
                         for (std::size_t derpIndex = 0; derpIndex < derps.size(); ++derpIndex)
                         {
                             if ((readyDerps[derpIndex] & EPOLLIN) == 0)
                             {
                                 continue;
                             }
                             DerpWorker& worker = *derps[derpIndex].Worker;
                             for (const tailgate::protocol::DerpClient::Packet& packet :
                                  worker.ReceivePackets())
                             {
                                 PeerRuntime* peer = peerForKey(packet.Source);
                                 if (peer == nullptr)
                                 {
                                     continue;
                                 }
                                 peer->RxBytes += packet.Payload.size();
                                 if (tailgate::protocol::Disco::IsDiscoPacket(packet.Payload))
                                 {
                                     PeerRuntime* discoPeer = nullptr;
                                     if (packet.Payload.size() >= 38)
                                     {
                                         tailgate::protocol::Bytes32 sender{};
                                         std::copy_n(packet.Payload.begin() + 6,
                                                     sender.size(),
                                                     sender.begin());
                                         discoPeer = peerForDiscoKey(sender);
                                     }
                                     if (discoPeer != nullptr)
                                     {
                                         handleDisco(*discoPeer,
                                                     packet.Payload,
                                                     std::nullopt,
                                                     &worker,
                                                     &packet.Source);
                                     }
                                     continue;
                                 }
                                 auto received =
                                     tunnel.ProcessPacket(peer->TunnelPeer, packet.Payload);
                                 if (received && !received->Reply.empty())
                                 {
                                     worker.Send(peer->PublicKey, received->Reply);
                                 }
                                 if (received && received->SessionEstablished)
                                 {
                                     tailgate::Log(tailgate::LogLevel::Debug,
                                                   "tunnel",
                                                   "session established peer=" + peer->Config.Name);
                                     flushPending(*peer);
                                 }
                                 if (received && !received->Plaintext.empty())
                                 {
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
            TimedSection(
                "timers",
                [&]()
                {
                    for (PeerRuntime& peer : peers)
                    {
                        if (peer.HasEndpoint && peer.AwaitingDirectResponse &&
                            std::chrono::steady_clock::now() - peer.FirstUnansweredDirectSend >
                                std::chrono::seconds(15))
                        {
                            peer.HasEndpoint = false;
                            peer.DirectProbeStarted = false;
                            peer.AwaitingDirectResponse = false;
                            tailgate::Log(tailgate::LogLevel::Info,
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
                            statusWriter.Submit(status);
                        }
                        if (tunnel.HasSession(peer.TunnelPeer) && !peer.HasEndpoint)
                        {
                            startDirectProbe(peer);
                        }
                        auto action = tunnel.UpdateTimers(peer.TunnelPeer);
                        if (action ==
                            tailgate::protocol::WireGuardTunnel::TimerAction::SendHandshake)
                        {
                            sendHandshake(peer);
                        }
                        else if (action ==
                                 tailgate::protocol::WireGuardTunnel::TimerAction::SendKeepalive)
                        {
                            sendPeer(peer, tunnel.Encrypt(peer.TunnelPeer, {}), false);
                        }
                        for (auto& peerStatus : status.Peers)
                        {
                            if (peerStatus.Address == peer.Config.Address)
                            {
                                peerStatus.Active = tunnel.HasSession(peer.TunnelPeer);
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
                            tailgate::Log(
                                tailgate::LogLevel::Warning,
                                "ping",
                                "timeout peer=" + pending.Peer->Config.Name + " online=" +
                                    std::to_string(pending.Peer->Config.Online ? 1 : 0) +
                                    " disco=" + std::to_string(pending.Peer->HasDiscoKey ? 1 : 0) +
                                    " endpoints=" +
                                    std::to_string(pending.Peer->Config.Endpoints.size()));
                            completePing(pending, false, {});
                        }
                        else if (pending.Peer != nullptr &&
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
                    if (readyFd >= 0 && tunnel.HasSession(dnsPeer->TunnelPeer) &&
                        (exitPeer == nullptr || tunnel.HasSession(exitPeer->TunnelPeer)))
                    {
                        const char ready = '1';
                        if (write(readyFd, &ready, 1) != 1)
                        {
                            tailgate::Log(tailgate::LogLevel::Warning,
                                          "daemon",
                                          "failed to notify parent that the tunnel is ready");
                        }
                        close(readyFd);
                        readyFd = -1;
                    }
                    if (now >= nextPeriodicStatus)
                    {
                        statusWriter.Submit(status);
                        nextPeriodicStatus = now + StatusRefreshInterval;
                    }
                });
        }
    }
    unlink(tailgate::linux_frontend::PingSocketPath().c_str());
}

void RunConnection(const std::string& authKey,
                   const tailgate::protocol::HostInfo& host,
                   const tailgate::protocol::Bytes32& machineKey,
                   const tailgate::protocol::Bytes32& nodePrivateKey,
                   bool acceptDns,
                   const std::string& exitNode,
                   tailgate::linux_frontend::DaemonStatus& status,
                   int& readyFd)
{
    tailgate::linux_frontend::TcpStream stream(
        tailgate::protocol::ControlHandshake::DefaultHost, "80", DefaultRouteInterface());
    tailgate::control::ControlClient control(stream, machineKey, nodePrivateKey, host);
    const tailgate::control::NetworkConfig config = control.RegisterAndGetNetworkMap(authKey);
    int derpRegion = config.DerpRegion;
    std::string derpHost = config.DerpHost;
    if (!exitNode.empty())
    {
        const auto selectedExitNode = tailgate::control::FindExitNode(config.Peers, exitNode, true);
        if (!selectedExitNode)
        {
            throw std::runtime_error("exit node was not found in the network map: " + exitNode);
        }
        const tailgate::control::PeerConfig& peer = config.Peers[*selectedExitNode];
        if (peer.DerpRegion == 0 || peer.DerpHost.empty())
        {
            throw std::runtime_error("exit node has no usable DERP region: " + exitNode);
        }
        derpRegion = peer.DerpRegion;
        derpHost = peer.DerpHost;
    }
    control.SetPreferredDerp(derpRegion);
    stream.SetNonBlocking(true);
    StartTunnel(nodePrivateKey,
                control.NodePublicKey(),
                control.DiscoPrivateKey(),
                config.SelfAddress,
                config.DnsResolver,
                config.DnsDomains,
                config.DnsDefaultResolvers,
                config.DnsRoutes,
                config.Peers,
                derpRegion,
                derpHost,
                exitNode,
                acceptDns,
                &control,
                stream.NativeHandle(),
                status,
                readyFd);
}

void Logout(const tailgate::protocol::HostInfo& host,
            const tailgate::protocol::Bytes32& machineKey,
            const tailgate::protocol::Bytes32& nodePrivateKey)
{
    tailgate::linux_frontend::TcpStream stream(
        tailgate::protocol::ControlHandshake::DefaultHost, "80", DefaultRouteInterface());
    tailgate::control::ControlClient control(stream, machineKey, nodePrivateKey, host);
    control.Logout();
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

tailgate::platform::UpResult RunUp(const tailgate::cli::UpOptions& options)
{
    const auto existing = tailgate::linux_frontend::ReadDaemonStatus();
    if (existing && tailgate::linux_frontend::IsProcessRunning(existing->ProcessId))
    {
        tailgate::linux_frontend::SettingsState settings =
            tailgate::linux_frontend::ReadSettings().value_or(
                tailgate::linux_frontend::SettingsState{});
        if (!options.Hostname.empty())
        {
            settings.Hostname = options.Hostname;
        }
        settings.ExitNode = options.ExitNode;
        settings.AcceptDns = options.AcceptDns;
        tailgate::linux_frontend::WriteSettings(settings);
        if (kill(existing->ProcessId, SIGUSR1) == 0)
        {
            return {true};
        }
        tailgate::Log(
            tailgate::LogLevel::Warning, "daemon", "stale Tailgate status; starting a new daemon");
        tailgate::linux_frontend::RemoveDaemonStatus();
    }

    tailgate::linux_frontend::RestoreResolverConfiguration();
    tailgate::linux_frontend::SaveResolverConfiguration();

    tailgate::protocol::HostInfo host = tailgate::linux_frontend::CollectHostInfo();
    if (!options.Hostname.empty())
    {
        host.Hostname = options.Hostname;
    }
    const std::string authKey = ResolveAuthKey(options.AuthKey);
    std::optional<tailgate::linux_frontend::IdentityState> identity =
        tailgate::linux_frontend::ReadIdentity();
    if (!identity && authKey.empty())
    {
        throw std::runtime_error("up requires --auth-key for the first connection");
    }
    if (identity && options.Hostname.empty() && !identity->Hostname.empty())
    {
        host.Hostname = identity->Hostname;
    }
    if (!identity)
    {
        identity = tailgate::linux_frontend::IdentityState{
            tailgate::protocol::GeneratePrivateKey(),
            tailgate::protocol::GeneratePrivateKey(),
            host.Hostname,
        };
        tailgate::linux_frontend::WriteIdentity(*identity);
    }
    else if (!options.Hostname.empty() && identity->Hostname != host.Hostname)
    {
        identity->Hostname = host.Hostname;
        tailgate::linux_frontend::WriteIdentity(*identity);
    }
    tailgate::linux_frontend::WriteSettings({host.Hostname, options.ExitNode, options.AcceptDns});

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
        char ready = 0;
        const ssize_t bytesRead = read(readyPipe[0], &ready, 1);
        if (bytesRead != 1)
        {
            ready = 0;
        }
        close(readyPipe[0]);
        if (ready == '1')
        {
            return {true};
        }
        else
        {
            return {false};
        }
    }

    close(readyPipe[0]);
    if (setsid() < 0)
    {
        _exit(1);
    }
    const pid_t daemonPid = fork();
    if (daemonPid < 0)
    {
        _exit(1);
    }
    if (daemonPid > 0)
    {
        _exit(0);
    }
    umask(0077);
    std::filesystem::create_directories(tailgate::linux_frontend::StateDirectory());
    constexpr const char* logPath = "/tmp/tailgate.log";
    const int logFd = open(logPath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
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

    tailgate::SetLogSink(
        [](tailgate::LogLevel level, const std::string& component, const std::string& message)
        {
            const auto now = std::chrono::system_clock::now();
            const auto seconds = std::chrono::time_point_cast<std::chrono::seconds>(now);
            const auto milliseconds =
                std::chrono::duration_cast<std::chrono::milliseconds>(now - seconds).count();
            const std::time_t timestamp = std::chrono::system_clock::to_time_t(now);
            std::tm utc{};
            gmtime_r(&timestamp, &utc);
            std::ostringstream line;
            line << std::put_time(&utc, "%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0')
                 << std::setw(3) << milliseconds << "Z [" << tailgate::LogLevelName(level) << "] "
                 << component << ": " << message << '\n';
            const std::string text = line.str();
            std::size_t offset = 0;
            while (offset < text.size())
            {
                const ssize_t written =
                    write(STDERR_FILENO, text.data() + offset, text.size() - offset);
                if (written > 0)
                {
                    offset += static_cast<std::size_t>(written);
                }
                else if (written < 0 && errno == EINTR)
                {
                    continue;
                }
                else
                {
                    break;
                }
            }
        });

    tailgate::Log(tailgate::LogLevel::Info,
                  "daemon",
                  "started pid=" + std::to_string(getpid()) + " hostname=" + host.Hostname +
                      " state=" + tailgate::linux_frontend::StateDirectory());

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
    status.ClientVersion = "Tailgate " TAILGATE_VERSION;
    tailgate::linux_frontend::WriteDaemonStatus(status);

    int retrySeconds = 1;
    int readyFd = readyPipe[1];
    const tailgate::protocol::Bytes32 machineKey = identity->MachinePrivateKey;
    const tailgate::protocol::Bytes32 nodePrivateKey = identity->NodePrivateKey;
    while (!StopRequested)
    {
        try
        {
            const auto settings = tailgate::linux_frontend::ReadSettings();
            if (settings && !settings->Hostname.empty())
            {
                host.Hostname = settings->Hostname;
            }
            ReloadRequested = 0;
            tailgate::linux_frontend::RestoreResolverConfiguration();
            const std::string selectedExitNode = settings ? settings->ExitNode : options.ExitNode;
            tailgate::Log(
                tailgate::LogLevel::Info,
                "daemon",
                "connecting hostname=" + host.Hostname + " accept-dns=" +
                    ((settings ? settings->AcceptDns : options.AcceptDns) ? "true" : "false") +
                    " exit-node=" + (selectedExitNode.empty() ? "none" : selectedExitNode));
            RunConnection(authKey,
                          host,
                          machineKey,
                          nodePrivateKey,
                          settings ? settings->AcceptDns : options.AcceptDns,
                          settings ? settings->ExitNode : options.ExitNode,
                          status,
                          readyFd);
            if (ReloadRequested)
            {
                tailgate::Log(tailgate::LogLevel::Info,
                              "daemon",
                              "settings changed; reconnecting data plane");
            }
            retrySeconds = 1;
        }
        catch (const std::exception& error)
        {
            tailgate::linux_frontend::RestoreResolverConfiguration();
            status.BackendState = "Starting";
            status.Online = false;
            status.Error = error.what();
            tailgate::linux_frontend::WriteDaemonStatus(status);
            tailgate::Log(tailgate::LogLevel::Error,
                          "daemon",
                          std::string(error.what()) + "; retrying in " +
                              std::to_string(retrySeconds) + " seconds");
            for (int elapsed = 0; elapsed < retrySeconds && !StopRequested; ++elapsed)
            {
                sleep(1);
            }
            retrySeconds = std::min(retrySeconds * 2, 30);
        }
    }

    tailgate::Log(tailgate::LogLevel::Info, "daemon", "shutdown requested");
    tailgate::linux_frontend::RestoreResolverConfiguration();
    try
    {
        Logout(host, machineKey, nodePrivateKey);
        tailgate::Log(tailgate::LogLevel::Info, "control", "node logout completed");
    }
    catch (const std::exception& error)
    {
        tailgate::Log(tailgate::LogLevel::Error,
                      "control",
                      "node logout failed: " + std::string(error.what()));
    }

    if (readyFd >= 0)
    {
        close(readyFd);
    }
    tailgate::linux_frontend::RemoveResolverBackup();
    tailgate::Log(tailgate::LogLevel::Info, "daemon", "shutdown complete");
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

    int Set(const cli::SetOptions& options) override
    {
        const auto existing = tailgate::linux_frontend::ReadDaemonStatus();
        if (!existing || !tailgate::linux_frontend::IsProcessRunning(existing->ProcessId))
        {
            throw std::runtime_error("Tailgate is not running");
        }
        tailgate::linux_frontend::SettingsState settings =
            tailgate::linux_frontend::ReadSettings().value_or(
                tailgate::linux_frontend::SettingsState{});
        if (options.Hostname)
        {
            settings.Hostname = *options.Hostname;
        }
        if (options.ExitNode)
        {
            if (!options.ExitNode->empty() && !HasOnlineExitNode(*existing, *options.ExitNode))
            {
                throw std::runtime_error("exit node is not online or was not found: " +
                                         *options.ExitNode);
            }
            settings.ExitNode = *options.ExitNode;
        }
        tailgate::linux_frontend::WriteSettings(settings);
        if (kill(existing->ProcessId, SIGUSR1) != 0)
        {
            throw std::runtime_error("failed to reload Tailgate settings");
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

    PingResult
    PingOnce(const std::string& target, int timeoutSeconds, std::uint16_t sequence) override
    {
        (void)sequence;
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        addrinfo* addresses = nullptr;
        const int result = getaddrinfo(target.c_str(), nullptr, &hints, &addresses);
        if (result != 0)
        {
            throw std::runtime_error("cannot resolve " + target + ": " +
                                     std::string(gai_strerror(result)));
        }
        std::string resolved;
        for (addrinfo* current = addresses; current != nullptr; current = current->ai_next)
        {
            const auto* address = reinterpret_cast<const sockaddr_in*>(current->ai_addr);
            char text[INET_ADDRSTRLEN]{};
            if (inet_ntop(AF_INET, &address->sin_addr, text, sizeof(text)) != nullptr)
            {
                resolved = text;
                break;
            }
        }
        freeaddrinfo(addresses);
        if (resolved.empty())
        {
            throw std::runtime_error("cannot resolve " + target + " to an IPv4 address");
        }
        return tailgate::linux_frontend::RequestDaemonPing(resolved, timeoutSeconds);
    }
};

} // namespace

std::unique_ptr<IPlatformFrontend> CreateFrontend()
{
    return std::make_unique<LinuxFrontend>();
}

} // namespace tailgate::platform
