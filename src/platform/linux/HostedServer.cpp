#include "HostedServer.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <exception>
#include <format>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include <sys/socket.h>

#include <tailgate/base/Logging.h>
#include <tailgate/hosted/DerpAuthenticator.h>
#include <tailgate/hosted/ServerSession.h>
#include <tailgate/hosted/ServerWriter.h>
#include <tailgate/ipn/ipnlocal/DelegatedNode.h>

#include "event/EventRegistry.h"

#include "DI.h"
#include "DataplaneEvents.h"
#include "DerpTransports.h"
#include "HostedConnectionRegistry.h"
#include "Lifecycle.h"
#include "Network.h"
#include "PacketDescriptorProvider.h"
#include "UniqueFd.h"

namespace
{

using tailgate::base::EventReadiness;
using tailgate::base::HasReadiness;
using tailgate::linux_frontend::DataplaneEvent;
using tailgate::linux_frontend::DefaultRouteInterface;
using tailgate::linux_frontend::InterfaceIpv4Address;
using tailgate::linux_frontend::ResolveIpv4UdpEndpoint;
using tailgate::linux_frontend::UniqueFd;
using tailgate::linux_frontend::event::EventInterest;
using tailgate::linux_frontend::event::EventRegistry;

constexpr auto StunResponseTimeout = std::chrono::seconds(3);

std::vector<tailgate::net::Endpoint>
DiscoverHostedEndpointCandidates(const std::string& underlayInterface,
                                 const tailgate::types::netmap::NetworkConfig& config,
                                 tailgate::wgengine::Session& session,
                                 const tailgate::wgengine::magicsock::Connection& connection)
{
    const std::optional<tailgate::net::Endpoint> socketEndpoint = connection.LocalEndpoint();
    if (!socketEndpoint)
    {
        throw std::system_error(std::make_error_code(std::errc::not_connected));
    }
    std::vector<tailgate::net::Endpoint> candidates{tailgate::net::Endpoint(
        tailgate::net::Ipv4Address::FromHostOrder(InterfaceIpv4Address(underlayInterface)),
        socketEndpoint->Port())};
    if (config.DerpRegion() == 0 || config.DerpHost().empty())
    {
        return candidates;
    }
    try
    {
        const tailgate::net::Endpoint stunServer = ResolveIpv4UdpEndpoint(
            config.StunHost().empty() ? config.DerpHost() : config.StunHost(), config.StunPort());
        const std::optional<tailgate::net::Endpoint> stunEndpoint =
            session.DiscoverEndpoint(stunServer, StunResponseTimeout);
        if (stunEndpoint &&
            std::find(candidates.begin(), candidates.end(), *stunEndpoint) == candidates.end())
        {
            candidates.insert(candidates.begin(), *stunEndpoint);
            tailgate::base::Log(tailgate::base::LogLevel::Info,
                                "relay",
                                std::format("hosted proxy discovered STUN endpoint {} via {}",
                                            stunEndpoint->ToString(),
                                            config.DerpHost()));
        }
    }
    catch (const std::exception& error)
    {
        tailgate::base::Log(tailgate::base::LogLevel::Warning,
                            "relay",
                            "failed to discover hosted proxy STUN endpoint: " +
                                std::string(error.what()));
    }
    return candidates;
}

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
    writeFrame(authenticationResult);

    const tailgate::hosted::Frame mapFrame = decoder.Read(stream);
    tailgate::types::netmap::NetworkConfig config =
        serverSession->AcceptInitialNetworkMap(mapFrame);
    markIdentityVerified();

    const std::string profileKey =
        tailgate::crypto::BytesToHex(authentication.Identity.NodePublicKey().data(),
                                     authentication.Identity.NodePublicKey().size());
    std::shared_ptr<tailgate::linux_frontend::HostedConnectionRegistration> active;
    const auto unregisterActive = [&]()
    {
        if (active)
        {
            hostedConnections.Unregister(profileKey, active);
        }
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
    std::mutex clientReadyMutex;
    std::condition_variable clientReadyChanged;
    bool clientReady = false;
    tailgate::di::Injector writerInjector;
    InstallBindings(writerInjector);
    writerInjector.create<PacketDescriptorProvider&>().Borrow(relayPackets.Fd);
    auto& hostedWriter = writerInjector.create<tailgate::hosted::ServerWriter&>();
    auto derpAuthenticator =
        std::make_shared<tailgate::hosted::DerpAuthenticator>(*serverSession, hostedWriter);
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
                    if (processed.PumpScheduleChanged)
                    {
                        hostedWriter.Wake();
                    }
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
                    if (processed.Delegation)
                    {
                        const auto encoded =
                            tailgate::hosted::EncodeDelegation(*processed.Delegation).Encode();
                        if (send(relayControls.Fd, encoded.data(), encoded.size(), MSG_NOSIGNAL) <
                            0)
                        {
                            throw std::system_error(
                                std::make_error_code(std::errc::connection_reset));
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
                        derpAuthenticator->AcceptResponse(std::move(*processed.DerpResponse));
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
            hostedWriter.Wake();
            clientReadyChanged.notify_all();
            shutdown(relayPackets.Fd, SHUT_RDWR);
            shutdown(relayControls.Fd, SHUT_RDWR);
        });
    std::thread serverWriter(
        [&]()
        {
            try
            {
                hostedWriter.Run(*serverSession, stream, writeMutex, stopping);
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
        const std::vector<tailgate::net::Endpoint> serverEndpointCandidates =
            DiscoverHostedEndpointCandidates(underlayInterface, config, networkSession, connection);
        const auto dataPathReady = [&]()
        {
            tailgate::linux_frontend::HostedConnectionRegistrationResult registration =
                hostedConnections.Register(
                    profileKey, closeConnection, authentication.Identity.NodeId());
            active = std::move(registration.Current);
            std::shared_ptr<tailgate::linux_frontend::HostedConnectionRegistration> previous =
                std::move(registration.Previous);
            if (previous)
            {
                constexpr std::chrono::seconds ReplacementTimeout(30);
                previous->Close();
                if (!previous->WaitForCompletion(ReplacementTimeout))
                {
                    throw std::runtime_error(
                        "previous relay connection did not stop during replacement");
                }
            }
            writeFrame(tailgate::hosted::Frame(
                tailgate::hosted::MessageType::ServerEndpointCandidates,
                tailgate::hosted::ProtocolCodec::EncodeServerEndpointCandidates(
                    tailgate::hosted::ServerEndpointCandidates(serverEndpointCandidates))));
            writeFrame(tailgate::hosted::Frame(tailgate::hosted::MessageType::DataPathReady, {}));
        };
        tailgate::derp::ConnectionOptions derpOptions;
        derpOptions.NetworkInterface = underlayInterface;
        derpOptions.PublicKey = authentication.Identity.NodePublicKey();
        derpOptions.Authenticator = derpAuthenticator;
        tailgate::linux_frontend::DerpTransports transports(derpConnectionFactory,
                                                            std::move(derpOptions));
        tailgate::ipn::ipnlocal::DelegatedNode node(
            networkSession,
            engine,
            connection,
            transports,
            networkInjector.create<tailgate::base::TimeProvider&>());
        node.Start(
            config,
            {.Name = {}, .ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::Tun).Token()});
        const auto controlToken = DataplaneEvent(DataplaneEvent::Kind::RelayControl).Token();
        auto controlEvent =
            eventRegistry.Register(brokerControls.Fd, EventInterest::Readable, controlToken);
        bool pathReady = false;
        std::vector<std::uint8_t> controlBuffer(tailgate::hosted::Frame::MaximumEncodedSize);
        while (!Lifecycle::Stopping() && !Lifecycle::Reloading())
        {
            constexpr std::size_t MaximumPacketsPerTurn = 16;
            constexpr std::size_t PacketBufferSize = 4096;
            auto completed =
                node.Wait(MaximumPacketsPerTurn, MaximumPacketsPerTurn, PacketBufferSize);
            for (auto& output : node.TakeControlOutput())
            {
                hostedWriter.Post(std::move(output));
            }
            if (!pathReady && node.Connected())
            {
                dataPathReady();
                pathReady = true;
            }
            for (const auto& event : completed.PlatformEvents)
            {
                if (event.Token == controlToken &&
                    HasReadiness(event.Readiness, EventReadiness::Readable))
                {
                    const auto count =
                        recv(brokerControls.Fd, controlBuffer.data(), controlBuffer.size(), 0);
                    if (count <= 0)
                    {
                        throw std::system_error(std::make_error_code(std::errc::connection_reset));
                    }
                    node.HandleControl(std::vector<std::uint8_t>(controlBuffer.begin(),
                                                                 controlBuffer.begin() + count));
                }
            }
        }
    }
    catch (...)
    {
        connectionError = std::current_exception();
    }
    stopping = true;
    closeConnection();
    hostedWriter.Wake();
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
