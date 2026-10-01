#include "DirectConnection.h"

#include <chrono>
#include <format>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <tailgate/control/client/Connection.h>
#include <tailgate/crypto/Certificate.h>
#include <tailgate/derp/Connection.h>
#include <tailgate/hosted/ServerSession.h>
#include <tailgate/ipn/ipnlocal/NativeNode.h>
#include <tailgate/ipn/ipnlocal/NodeBootstrap.h>
#include <tailgate/ipn/ipnlocal/SwitchingNode.h>
#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/http/Client.h>
#include <tailgate/wgengine/Engine.h>
#include <tailgate/wgengine/Session.h>
#include <tailgate/wgengine/magicsock/Bind.h>
#include <tailgate/wgengine/magicsock/Connection.h>

#include "event/EventRegistry.h"

#include "BootstrapPlatform.h"
#include "DI.h"
#include "DataplaneEvents.h"
#include "DerpTransports.h"
#include "HostedConnectionRegistry.h"
#include "HostedServer.h"
#include "ModeControl.h"
#include "Network.h"
#include "NodeHost.h"
#include "RelayServer.h"
#include "State.h"

namespace tailgate::linux_frontend
{

using tailgate::linux_frontend::DataplaneEvent;
using tailgate::linux_frontend::DefaultRouteInterface;
using tailgate::linux_frontend::InterfaceIpv4Address;
using tailgate::linux_frontend::ResolveIpv4UdpEndpoint;
using tailgate::linux_frontend::event::EventRegistry;

constexpr int ExposeLocalPort = 41113;
constexpr auto UdpBindTimeout = std::chrono::seconds(10);

void RunDirectConnection(const std::string& authKey,
                         tailgate::control::client::HostInfo host,
                         const tailgate::crypto::Bytes32& machineKey,
                         const tailgate::crypto::Bytes32& nodePrivateKey,
                         const tailgate::crypto::Bytes32& discoPrivateKey,
                         bool acceptDns,
                         const std::string& exitNode,
                         int funnelPort,
                         int funnelLocalPort,
                         int exposePort,
                         tailgate::linux_frontend::DaemonStatus& status,
                         int& readyFd,
                         const std::string& followupUrl,
                         tailgate::linux_frontend::Registration& registrationHandler,
                         const std::string& reauthorizationKey)
{
    const tailgate::serve::FunnelConfig funnel =
        tailgate::serve::TlsTerminatedTcpFunnel(funnelPort, funnelLocalPort);
    tailgate::ipn::ipnlocal::NodeBootstrap::ConfigureHost(funnel, host);
    const std::string underlayInterface = DefaultRouteInterface();
    tailgate::di::Injector networkInjector;
    tailgate::linux_frontend::InstallBindings(networkInjector);
    EventRegistry& eventRegistry = networkInjector.create<EventRegistry&>();
    tailgate::wgengine::Engine& engine = networkInjector.create<tailgate::wgengine::Engine&>();
    tailgate::wgengine::Session& session = networkInjector.create<tailgate::wgengine::Session&>();
    tailgate::wgengine::magicsock::Connection& connection =
        networkInjector.create<tailgate::wgengine::magicsock::Connection&>();
    tailgate::derp::ConnectionFactory& derpConnectionFactory =
        networkInjector.create<tailgate::derp::ConnectionFactory&>();
    tailgate::control::client::ConnectionFactory& controlConnectionFactory =
        networkInjector.create<tailgate::control::client::ConnectionFactory&>();
    tailgate::hosted::ServerSessionFactory& hostedServerSessionFactory =
        networkInjector.create<tailgate::hosted::ServerSessionFactory&>();
    auto& hostedConnections =
        networkInjector.create<tailgate::linux_frontend::HostedConnectionRegistry&>();
    std::unique_ptr<tailgate::control::client::Connection> ownedControl =
        controlConnectionFactory.CreateConnection(tailgate::control::client::SessionOptions{
            .Host = host,
            .MachinePrivateKey = machineKey,
            .NodePrivateKey = nodePrivateKey,
            .ExternalNodePublicKey = std::nullopt,
            .NetworkInterface = underlayInterface,
            .ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::RelayControl).Token(),
        });
    tailgate::control::client::Connection& control = *ownedControl;
    control.SetDiscoPrivateKey(discoPrivateKey);
    const auto sharedEndpoint = tailgate::wgengine::magicsock::Bind(
        connection,
        tailgate::types::nettype::UdpSocketOptions{
            .BindEndpoint = {},
            .NetworkInterface = underlayInterface,
            .ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::AdvertisedUdp).Token(),
        },
        networkInjector.create<tailgate::base::EventLoop&>(),
        networkInjector.create<tailgate::base::TimeProvider&>(),
        UdpBindTimeout);
    tailgate::linux_frontend::BootstrapPlatform platform(registrationHandler, hostedConnections);
    tailgate::ipn::ipnlocal::NodeBootstrap bootstrap(
        control,
        session,
        networkInjector.create<tailgate::net::http::Client&>(),
        networkInjector.create<tailgate::crypto::Certificate&>(),
        platform);
    const auto prepared = bootstrap.Start(
        authKey,
        tailgate::control::client::RegistrationOptions{.InitialFollowupUrl = followupUrl,
                                                       .ReauthorizationKey = reauthorizationKey,
                                                       .Handler = &registrationHandler},
        tailgate::net::Endpoint(
            tailgate::net::Ipv4Address::FromHostOrder(InterfaceIpv4Address(underlayInterface)),
            sharedEndpoint.Port()),
        funnel,
        exitNode);
    const auto& config = prepared.Network;
    hostedConnections.UpdateNetworkMap(config);
    std::unique_ptr<tailgate::linux_frontend::RelayServer> relayServer;
    if (exposePort != 0)
    {
        relayServer = std::make_unique<tailgate::linux_frontend::RelayServer>(
            ExposeLocalPort,
            [&hostedServerSessionFactory,
             &hostedConnections,
             &control,
             domain = config.Domain(),
             relayHostName = config.DisplayName(),
             relayHostAddress = config.SelfAddress(),
             relayPrivateKey = nodePrivateKey,
             relayPublicKey =
                 control.NodePublicKey()](tailgate::base::ByteStream& relay,
                                          const std::function<void()>& closeConnection,
                                          const std::function<void()>& markIdentityVerified)
            {
                tailgate::linux_frontend::RunHostedServer(hostedServerSessionFactory,
                                                          hostedConnections,
                                                          control,
                                                          relay,
                                                          domain,
                                                          relayHostName,
                                                          relayHostAddress,
                                                          relayPrivateKey,
                                                          relayPublicKey,
                                                          closeConnection,
                                                          markIdentityVerified);
            });
    }
    session.SetControlConnection(std::move(ownedControl));
    tailgate::derp::ConnectionOptions derpOptions;
    derpOptions.NetworkInterface = underlayInterface;
    derpOptions.PrivateKey = nodePrivateKey;
    derpOptions.PublicKey = control.NodePublicKey();
    tailgate::linux_frontend::DerpTransports transports(derpConnectionFactory,
                                                        std::move(derpOptions));
    auto& time = networkInjector.create<tailgate::base::TimeProvider&>();
    tailgate::ipn::ipnlocal::NativeNode node(
        session,
        engine,
        connection,
        networkInjector.create<tailgate::ipn::ipnlocal::LocalServices&>(),
        networkInjector.create<tailgate::ipn::ipnlocal::DnsForwarder&>(),
        networkInjector.create<tailgate::wgengine::ping::Tracker&>(),
        time,
        transports);
    node.Start(
        config,
        {.NodePrivateKey = nodePrivateKey,
         .NodePublicKey = control.NodePublicKey(),
         .DiscoPrivateKey = control.DiscoPrivateKey(),
         .AdvertisedEndpoint = tailgate::net::Endpoint(
             tailgate::net::Ipv4Address::FromHostOrder(InterfaceIpv4Address(underlayInterface)),
             sharedEndpoint.Port()),
         .HomeDerpRegion = prepared.DerpRegion,
         .Peers = {},
         .ExitNode = exitNode},
        {.Name = "tailgate0", .ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::Tun).Token()},
        {.BindEndpoint = {},
         .NetworkInterface = underlayInterface,
         .ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::AdvertisedUdp).Token()},
        prepared.StunServer);
    tailgate::ipn::ipnlocal::HostedNode hostedNode(
        networkInjector.create<tailgate::hosted::Client&>(),
        session,
        engine,
        networkInjector.create<tailgate::ipn::ipnlocal::LocalServices&>(),
        networkInjector.create<tailgate::ipn::ipnlocal::DnsForwarder&>(),
        networkInjector.create<tailgate::wgengine::ping::Tracker&>(),
        time,
        networkInjector.create<tailgate::hosted::Dns&>(),
        networkInjector.create<tailgate::hosted::Recovery&>());
    tailgate::hosted::Recovery preparation(
        networkInjector.create<tailgate::types::nettype::TcpSocketFactory&>(),
        networkInjector.create<tailgate::base::EventLoop&>(),
        time);
    tailgate::ipn::ipnlocal::SwitchingNode switching(
        node,
        hostedNode,
        preparation,
        time,
        tailgate::ipn::ipnlocal::NodeMode::Native,
        {.Name = "tailgate0", .ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::Tun).Token()},
        exitNode);
    tailgate::hosted::ConnectionOptions relayOptions;
    relayOptions.Socket.NetworkInterface = underlayInterface;
    relayOptions.Socket.ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::Control).Token();
    relayOptions.Socket.NonBlockingAfterConnect = true;
    relayOptions.Hostname = host.Hostname();
    relayOptions.OperatingSystem = host.OperatingSystem();
    relayOptions.OperatingSystemVersion = host.OperatingSystemVersion();
    relayOptions.Client = {.NodePrivateKey = nodePrivateKey,
                           .NodePublicKey = control.NodePublicKey(),
                           .DiscoPrivateKey = discoPrivateKey,
                           .Network = config,
                           .ExitNode = exitNode};
    ModeControl modes(switching, std::move(relayOptions));
    tailgate::linux_frontend::NodeHost hostSession(
        switching, session, eventRegistry, hostedConnections, time, status);
    hostSession.Run({.InterfaceName = "tailgate0",
                     .UnderlayInterface = underlayInterface,
                     .AcceptDns = acceptDns,
                     .Funnel = funnel,
                     .CertificatePem = prepared.CertificatePem,
                     .PrivateKeyPem = prepared.PrivateKeyPem,
                     .RelayName = {}},
                    readyFd,
                    modes,
                    networkInjector.create<tailgate::base::EventLoop&>());
}

} // namespace tailgate::linux_frontend
