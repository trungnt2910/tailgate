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
#include <tailgate/hosted/Connection.h>
#include <tailgate/hosted/DiscoProbes.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/hosted/ServerSession.h>
#include <tailgate/net/dns/Dns.h>
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
#include "Network.h"
#include "PacketDescriptorProvider.h"
#include "PeerApiServer.h"
#include "PingIpc.h"
#include "QrCode.h"
#include "RelayServer.h"
#include "State.h"
#include "StatusWriter.h"
#include "UniqueFd.h"
#include "event/EventRegistry.h"
#include "impl/EventLoop.h"
#include "impl/TimeProvider.h"

#include "HostedServer.h"
#include "Lifecycle.h"
#include "TunnelRunner.h"

namespace
{

using tailgate::linux_frontend::AddRoute;
using tailgate::linux_frontend::DataplaneEvent;
using tailgate::linux_frontend::DefaultRouteInterface;
using tailgate::linux_frontend::InterfaceIpv4Address;
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
using tailgate::linux_frontend::event::EventInterest;
using tailgate::linux_frontend::event::EventRegistry;
using Ipv4Prefix = tailgate::net::packet::Ipv4Prefix;
using TailPeer = tailgate::types::netmap::PeerConfig;
using tailgate::base::EventReadiness;
using tailgate::base::HasReadiness;

constexpr auto RelayHeartbeatInterval = std::chrono::seconds(20);
constexpr std::size_t MaximumRelayPacketBatch = 64;
constexpr std::size_t RelayPacketBufferSize = 4096;

} // namespace

namespace tailgate::linux_frontend
{

void RunHostedServer(tailgate::hosted::ServerSessionFactory& sessionFactory,
                     tailgate::linux_frontend::HostedConnectionRegistry& hostedConnections,
                     tailgate::control::client::Connection& control,
                     tailgate::base::ByteStream& stream,
                     const std::string& expectedDomain,
                     const std::string& relayHostName,
                     const std::string& relayHostAddress,
                     const tailgate::crypto::Bytes32& relayPrivateKey,
                     const tailgate::crypto::Bytes32& relayPublicKey,
                     const std::function<void()>& closeConnection,
                     const std::function<void()>& markIdentityVerified)
{
    tailgate::hosted::Decoder decoder;
    std::unique_ptr<tailgate::hosted::ServerSession> serverSession =
        sessionFactory.CreateServerSession(tailgate::hosted::ServerSessionOptions{
            .ExpectedTailnet = expectedDomain,
            .RelayHostName = relayHostName,
            .RelayHostAddress = relayHostAddress,
            .RelayPrivateKey = relayPrivateKey,
            .RelayPublicKey = relayPublicKey,
        });
    serverSession->StartAuthentication().Write(stream);
    const tailgate::hosted::Frame authenticationFrame = decoder.Read(stream);
    const tailgate::hosted::ServerAuthenticationResult authentication =
        serverSession->EvaluateAuthentication(authenticationFrame);
    tailgate::linux_frontend::HostedNodeVisibility visibility =
        tailgate::linux_frontend::HostedNodeVisibility::TimedOut;
    if (authentication.ProofValid && authentication.TailnetMatches)
    {
        if (!hostedConnections.IsNodeVisible(authentication.Identity.Tailnet(),
                                             authentication.Identity.NodeId(),
                                             authentication.Identity.NodePublicKey()))
        {
            tailgate::base::Log(
                tailgate::base::LogLevel::Info,
                "relay",
                "hosted node is absent from the live map; requesting a full control map");
            control.RequestReconnect();
        }
        constexpr std::chrono::seconds VisibilityTimeout(30);
        visibility =
            hostedConnections.WaitForNodeVisibility(authentication.Identity.Tailnet(),
                                                    authentication.Identity.NodeId(),
                                                    authentication.Identity.NodePublicKey(),
                                                    VisibilityTimeout);
        if (visibility == tailgate::linux_frontend::HostedNodeVisibility::TimedOut)
        {
            tailgate::base::Log(
                tailgate::base::LogLevel::Warning,
                "relay",
                "control map did not refresh while checking hosted node visibility");
        }
    }
    const bool nodeVisible = visibility == tailgate::linux_frontend::HostedNodeVisibility::Visible;
    const tailgate::hosted::Frame authenticationResult =
        serverSession->CompleteAuthentication(nodeVisible);
    if (authenticationResult.Type() == tailgate::hosted::MessageType::Rejected)
    {
        tailgate::base::Log(
            tailgate::base::LogLevel::Warning,
            "relay",
            std::format("rejecting hosted authentication node-id={} proof={} tailnet={} "
                        "visibility={}",
                        authentication.Identity.NodeId(),
                        authentication.ProofValid ? "valid" : "invalid",
                        authentication.TailnetMatches ? "match" : "mismatch",
                        nodeVisible ? "visible" : "missing"));
        authenticationResult.Write(stream);
        return;
    }

    std::mutex writeMutex;
    const auto writeFrame = [&](tailgate::hosted::Frame frame)
    {
        std::lock_guard lock(writeMutex);
        frame.Write(stream);
    };
    const auto writeFrames = [&](const std::vector<tailgate::hosted::Frame>& frames)
    {
        std::lock_guard lock(writeMutex);
        stream.WriteAll(tailgate::hosted::Frame::EncodeAll(frames));
    };
    writeFrame(authenticationResult);

    const tailgate::hosted::Frame mapFrame = decoder.Read(stream);
    tailgate::types::netmap::NetworkConfig config =
        serverSession->AcceptInitialNetworkMap(mapFrame);
    markIdentityVerified();

    const std::string profileKey =
        tailgate::crypto::BytesToHex(authentication.Identity.NodePublicKey().data(),
                                     authentication.Identity.NodePublicKey().size());
    tailgate::linux_frontend::HostedConnectionRegistrationResult registration =
        hostedConnections.Register(profileKey, closeConnection, authentication.Identity.NodeId());
    const std::shared_ptr<tailgate::linux_frontend::HostedConnectionRegistration> active =
        registration.Current;
    std::shared_ptr<tailgate::linux_frontend::HostedConnectionRegistration> previous =
        std::move(registration.Previous);
    if (previous)
    {
        constexpr std::chrono::seconds ReplacementTimeout(30);
        previous->Close();
        if (!previous->WaitForCompletion(ReplacementTimeout))
        {
            throw std::runtime_error("previous relay connection did not stop during replacement");
        }
        previous.reset();
    }
    const auto unregisterActive = [&]()
    {
        hostedConnections.Unregister(profileKey, active);
    };

    int packets[2]{};
    int controls[2]{};
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, packets) != 0 ||
        socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, controls) != 0)
    {
        unregisterActive();
        throw std::runtime_error("relay transport socketpair failed: " +
                                 std::string(std::strerror(errno)));
    }
    UniqueFd relayPackets(packets[0]);
    UniqueFd brokerPackets(packets[1]);
    UniqueFd relayControls(controls[0]);
    UniqueFd brokerControls(controls[1]);
    std::atomic<bool> stopping = false;
    std::mutex derpMutex;
    std::condition_variable derpChanged;
    std::mutex clientReadyMutex;
    std::condition_variable clientReadyChanged;
    bool clientReady = false;
    std::map<std::uint64_t, std::optional<std::vector<std::uint8_t>>> derpResponses;
    const tailgate::derp::DerpClient::Authenticator derpAuthenticator =
        [&](const tailgate::derp::DerpClient::Key& serverKey)
    {
        const tailgate::hosted::ServerDerpChallenge challenge =
            serverSession->BuildDerpChallenge(serverKey);
        {
            std::lock_guard lock(derpMutex);
            derpResponses.emplace(challenge.RequestId, std::nullopt);
        }
        writeFrame(challenge.Output);
        constexpr std::chrono::seconds AuthenticationTimeout(30);
        std::unique_lock lock(derpMutex);
        const bool completed = derpChanged.wait_for(
            lock,
            AuthenticationTimeout,
            [&]()
            {
                const auto found = derpResponses.find(challenge.RequestId);
                return stopping || (found != derpResponses.end() && found->second.has_value());
            });
        const auto found = derpResponses.find(challenge.RequestId);
        if (!completed || found == derpResponses.end() || !found->second)
        {
            derpResponses.erase(challenge.RequestId);
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
                    const tailgate::hosted::Frame frame = decoder.Read(stream);
                    tailgate::hosted::ServerSessionProcessResult processed =
                        serverSession->Process(frame);
                    if (processed.PeerPacketPayload)
                    {
                        if (send(relayPackets.Fd,
                                 processed.PeerPacketPayload->data(),
                                 processed.PeerPacketPayload->size(),
                                 MSG_NOSIGNAL) < 0)
                        {
                            throw std::runtime_error("relay packet forwarding failed");
                        }
                    }
                    if (processed.NetworkMap)
                    {
                        const std::vector<std::uint8_t> encoded =
                            tailgate::hosted::Frame(
                                tailgate::hosted::MessageType::NetworkMap,
                                tailgate::hosted::ProtocolCodec::EncodeNetworkConfig(
                                    *processed.NetworkMap))
                                .Encode();
                        if (send(relayControls.Fd, encoded.data(), encoded.size(), MSG_NOSIGNAL) <
                            0)
                        {
                            throw std::runtime_error("relay network-map forwarding failed");
                        }
                    }
                    if (processed.VerifiedPeerEndpoint)
                    {
                        const std::vector<std::uint8_t> encoded =
                            tailgate::hosted::Frame(
                                tailgate::hosted::MessageType::PeerEndpoint,
                                tailgate::hosted::ProtocolCodec::EncodePeerEndpoint(
                                    *processed.VerifiedPeerEndpoint))
                                .Encode();
                        if (send(relayControls.Fd, encoded.data(), encoded.size(), MSG_NOSIGNAL) <
                            0)
                        {
                            throw std::runtime_error("relay endpoint forwarding failed");
                        }
                    }
                    if (processed.DnsName)
                    {
                        tailgate::base::Log(
                            tailgate::base::LogLevel::Info,
                            "dns",
                            std::format("answered hosted Tailnet DNS query name={} node-id={}",
                                        *processed.DnsName,
                                        authentication.Identity.NodeId()));
                    }
                    for (tailgate::hosted::Frame& output : processed.RemoteOutput)
                    {
                        writeFrame(std::move(output));
                    }
                    if (processed.DerpResponse)
                    {
                        {
                            std::lock_guard lock(derpMutex);
                            const auto found =
                                derpResponses.find(processed.DerpResponse->RequestId());
                            if (found == derpResponses.end() || found->second)
                            {
                                throw std::runtime_error("unexpected DERP authentication response");
                            }
                            found->second = std::move(processed.DerpResponse->ClientInfo());
                        }
                        derpChanged.notify_all();
                    }
                    if (processed.ClientReady)
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
                    if (processed.Shutdown)
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
            shutdown(relayControls.Fd, SHUT_RDWR);
        });
    std::thread serverWriter(
        [&]()
        {
            try
            {
                std::vector<std::uint8_t> packet(RelayPacketBufferSize);
                const std::shared_ptr<EventRegistry> writerRegistry =
                    std::make_shared<EventRegistry>();
                const tailgate::linux_frontend::event::EventHandle packetEvent =
                    writerRegistry->Register(
                        relayPackets.Fd,
                        EventInterest::Readable,
                        DataplaneEvent(DataplaneEvent::Kind::RelayControl).Token());
                tailgate::linux_frontend::impl::EventLoop writerLoop(writerRegistry);
                tailgate::linux_frontend::impl::TimeProvider writerTime;
                while (!stopping)
                {
                    std::unique_ptr<tailgate::base::WaitToken> heartbeat =
                        writerTime.After(RelayHeartbeatInterval);
                    const tailgate::base::EventWaitResult ready = writerLoop.Wait(*heartbeat, 1);
                    if (ready.Status == tailgate::base::EventWaitStatus::Woken)
                    {
                        continue;
                    }
                    if (ready.Status == tailgate::base::EventWaitStatus::DeadlineReached)
                    {
                        // The server drives the heartbeat so clients without their own
                        // timers (UWP) get a periodic opportunity to run WireGuard timers
                        // and send DERP-bound packets.
                        writeFrame(serverSession->BuildHeartbeat());
                        continue;
                    }
                    if (ready.Events.empty() ||
                        !HasReadiness(ready.Events.front().Readiness, EventReadiness::Readable))
                    {
                        break;
                    }
                    std::vector<tailgate::hosted::Frame> frames;
                    for (std::size_t index = 0; index < MaximumRelayPacketBatch; ++index)
                    {
                        const ssize_t received =
                            recv(relayPackets.Fd, packet.data(), packet.size(), MSG_DONTWAIT);
                        if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                        {
                            break;
                        }
                        if (received <= 0)
                        {
                            stopping = true;
                            break;
                        }
                        frames.push_back(serverSession->BuildServerPacket(
                            std::vector<std::uint8_t>(packet.begin(), packet.begin() + received)));
                    }
                    if (!frames.empty())
                    {
                        writeFrames(frames);
                    }
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
        tailgate::base::Log(tailgate::base::LogLevel::Info,
                            "relay",
                            std::format("hosted client data path ready node-id={}",
                                        authentication.Identity.NodeId()));
        const std::string underlayInterface = DefaultRouteInterface();
        tailgate::di::Injector networkInjector;
        tailgate::linux_frontend::InstallBindings(networkInjector);
        networkInjector.create<tailgate::linux_frontend::PacketDescriptorProvider&>().Borrow(
            brokerPackets.Fd);
        EventRegistry& eventRegistry = networkInjector.create<EventRegistry&>();
        tailgate::wgengine::Engine& engine = networkInjector.create<tailgate::wgengine::Engine&>();
        tailgate::wgengine::Session& networkSession =
            networkInjector.create<tailgate::wgengine::Session&>();
        tailgate::wgengine::magicsock::Connection& connection =
            networkInjector.create<tailgate::wgengine::magicsock::Connection&>();
        tailgate::derp::ConnectionFactory& derpConnectionFactory =
            networkInjector.create<tailgate::derp::ConnectionFactory&>();
        if (!connection.Open(tailgate::types::nettype::UdpSocketOptions{
                .BindEndpoint = {},
                .NetworkInterface = underlayInterface,
                .ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::AdvertisedUdp).Token(),
            }))
        {
            throw std::system_error(std::make_error_code(std::errc::address_not_available));
        }
        tailgate::linux_frontend::DaemonStatus hostedStatus;
        int readyFd = -1;
        tailgate::linux_frontend::RunTunnel(
            {},
            authentication.Identity.NodePublicKey(),
            {},
            config.SelfAddress(),
            config.FirstIpv6Address(),
            config.SelfName(),
            config.MagicDnsDomain().empty() ? config.Domain() : config.MagicDnsDomain(),
            config.DnsResolver(),
            config.DnsDomains(),
            config.DnsDefaultResolvers(),
            config.DnsRoutes(),
            config.Peers(),
            config.DerpRegion(),
            config.DerpHost(),
            "",
            false,
            {},
            {},
            {},
            {},
            eventRegistry,
            engine,
            networkSession,
            connection,
            derpConnectionFactory,
            hostedConnections,
            hostedStatus,
            readyFd,
            false,
            false,
            true,
            brokerControls.Fd,
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
    shutdown(relayControls.Fd, SHUT_RDWR);
    clientReader.join();
    serverWriter.join();
    unregisterActive();
    if (connectionError)
    {
        std::rethrow_exception(connectionError);
    }
}

} // namespace tailgate::linux_frontend
