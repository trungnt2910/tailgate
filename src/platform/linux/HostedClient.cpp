#include "HostedClient.h"

#include <algorithm>
#include <chrono>
#include <format>
#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>

#include <tailgate/base/Logging.h>
#include <tailgate/control/client/Connection.h>
#include <tailgate/hosted/Connection.h>
#include <tailgate/hosted/RelayEndpoint.h>
#include <tailgate/ipn/ipnlocal/HostedNode.h>
#include <tailgate/ipn/ipnlocal/NodeBootstrap.h>
#include <tailgate/ipn/ipnlocal/SwitchingNode.h>

#include "event/EventRegistry.h"
#include "impl/TcpStream.h"

#include "DI.h"
#include "DataplaneEvents.h"
#include "DerpTransports.h"
#include "HostedConnectionRegistry.h"
#include "ModeControl.h"
#include "Network.h"
#include "NodeHost.h"
#include "State.h"

namespace tailgate::linux_frontend
{

using event::EventRegistry;

void RunHostedClient(const std::string& url,
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
    auto endpoint = tailgate::hosted::RelayEndpoint::Parse(url);
    endpoint.Resolve(tcpSocketFactory, underlayInterface, addressAttempt);
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
    auto prepared = tailgate::ipn::ipnlocal::NodeBootstrap::RegisterHosted(
        control, authKey, registrationOptions, exitNode);
    auto config = std::move(prepared.Network);
    const auto& effectiveExitNode = prepared.ExitNode;
    registrationHandler.Accepted();
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
    auto& networkSession = networkInjector.create<tailgate::wgengine::Session&>();
    networkSession.SetControlConnection(std::move(ownedControl));
    control.StartStreaming();
    auto& time = networkInjector.create<tailgate::base::TimeProvider&>();
    auto& localServices = networkInjector.create<tailgate::ipn::ipnlocal::LocalServices&>();
    tailgate::derp::ConnectionOptions derpOptions;
    derpOptions.NetworkInterface = underlayInterface;
    derpOptions.PrivateKey = nodePrivateKey;
    derpOptions.PublicKey = control.NodePublicKey();
    DerpTransports derps(networkInjector.create<tailgate::derp::ConnectionFactory&>(),
                         std::move(derpOptions));
    tailgate::ipn::ipnlocal::NativeNode nativeNode(
        networkSession,
        networkInjector.create<tailgate::wgengine::Engine&>(),
        networkInjector.create<tailgate::wgengine::magicsock::Connection&>(),
        localServices,
        networkInjector.create<tailgate::ipn::ipnlocal::DnsForwarder&>(),
        pingTracker,
        time,
        derps);
    nativeNode.Start(
        config,
        {.NodePrivateKey = nodePrivateKey,
         .NodePublicKey = control.NodePublicKey(),
         .DiscoPrivateKey = discoPrivateKey,
         .AdvertisedEndpoint = {},
         .HomeDerpRegion = config.DerpRegion(),
         .Peers = {},
         .ExitNode = exitNode},
        {.Name = "tailgate0", .ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::Tun).Token()},
        {.BindEndpoint = {},
         .NetworkInterface = underlayInterface,
         .ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::AdvertisedUdp).Token()},
        std::nullopt,
        false);
    auto relayOptions = hosted.Reconnect;
    tailgate::ipn::ipnlocal::HostedNode node(
        hostedClient,
        networkSession,
        networkInjector.create<tailgate::wgengine::Engine&>(),
        localServices,
        networkInjector.create<tailgate::ipn::ipnlocal::DnsForwarder&>(),
        pingTracker,
        time,
        hostedDns,
        networkInjector.create<tailgate::hosted::Recovery&>());
    node.Start(
        std::move(hosted),
        {.Name = "tailgate0", .ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::Tun).Token()},
        exitNode,
        relayHostName);
    tailgate::hosted::Recovery preparation(
        tcpSocketFactory, networkInjector.create<tailgate::base::EventLoop&>(), time);
    tailgate::ipn::ipnlocal::SwitchingNode switching(
        nativeNode,
        node,
        preparation,
        time,
        tailgate::ipn::ipnlocal::NodeMode::Hosted,
        {.Name = "tailgate0", .ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::Tun).Token()},
        exitNode);
    ModeControl modes(switching, std::move(relayOptions));
    tailgate::linux_frontend::NodeHost hostAdapter(
        switching,
        networkSession,
        networkInjector.create<EventRegistry&>(),
        networkInjector.create<tailgate::linux_frontend::HostedConnectionRegistry&>(),
        time,
        status);
    hostAdapter.Run({.InterfaceName = "tailgate0",
                     .UnderlayInterface = underlayInterface,
                     .AcceptDns = acceptDns,
                     .Funnel = {},
                     .CertificatePem = {},
                     .PrivateKeyPem = {},
                     .RelayName = relayHostName},
                    readyFd,
                    modes,
                    networkInjector.create<tailgate::base::EventLoop&>());
    localServices.Stop();
}

} // namespace tailgate::linux_frontend
