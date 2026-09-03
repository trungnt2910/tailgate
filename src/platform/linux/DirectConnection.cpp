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
#include <tailgate/crypto/Certificate.h>
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
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/http/Client.h>
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
#include "PeerApiServer.h"
#include "PingIpc.h"
#include "QrCode.h"
#include "RelayServer.h"
#include "State.h"
#include "StatusWriter.h"
#include "UniqueFd.h"
#include "event/EventRegistry.h"

#include "DirectConnection.h"
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
using tailgate::linux_frontend::ResolveIpv4UdpEndpoint;
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

constexpr int ExposeLocalPort = 41113;
constexpr int FunnelPeerApiPort = 41112;
constexpr auto StunResponseTimeout = std::chrono::seconds(3);

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

class ControlDnsPublisher final : public tailgate::serve::acme::ChallengePublisher
{
public:
    explicit ControlDnsPublisher(tailgate::control::client::Connection& control)
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
    tailgate::control::client::Connection& m_control;
};

void RunConnectionImpl(const std::string& authKey,
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
    tailgate::serve::ApplyToHostInfo(funnel, host);
    if (tailgate::serve::IsEnabled(funnel))
    {
        host.AddService(tailgate::control::client::HostService{.Protocol = "peerapi4",
                                                               .Port = FunnelPeerApiPort});
        host.AddService(tailgate::control::client::HostService{.Protocol = "peerapi6",
                                                               .Port = FunnelPeerApiPort});
        host.AddService(
            tailgate::control::client::HostService{.Protocol = "peerapi-dns-proxy", .Port = 1});
        tailgate::base::Log(
            tailgate::base::LogLevel::Info,
            "control",
            std::format("advertising funnel hostinfo: ingress={} wire-ingress={} peerapi-port={}",
                        host.IngressEnabled() ? 1 : 0,
                        host.WireIngress() ? 1 : 0,
                        FunnelPeerApiPort));
    }
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
            .ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::Control).Token(),
        });
    tailgate::control::client::Connection& control = *ownedControl;
    control.SetDiscoPrivateKey(discoPrivateKey);
    if (!connection.Open(tailgate::types::nettype::UdpSocketOptions{
            .BindEndpoint = {},
            .NetworkInterface = underlayInterface,
            .ReadinessToken = DataplaneEvent(DataplaneEvent::Kind::AdvertisedUdp).Token(),
        }))
    {
        throw std::system_error(std::make_error_code(std::errc::address_not_available));
    }
    const std::optional<tailgate::net::Endpoint> sharedEndpoint = connection.LocalEndpoint();
    if (!sharedEndpoint)
    {
        throw std::system_error(std::make_error_code(std::errc::not_connected));
    }
    const std::string localEndpoint = std::format(
        "{}:{}",
        tailgate::net::Ipv4Address::FromHostOrder(InterfaceIpv4Address(underlayInterface))
            .ToString(),
        sharedEndpoint->Port());
    std::vector<tailgate::control::client::MapEndpoint> advertisedEndpoints{
        tailgate::control::client::MapEndpoint{
            .AddressPort = localEndpoint, .Type = tailgate::control::client::EndpointType::Local}};
    control.SetEndpoints(advertisedEndpoints);
    tailgate::base::Log(
        tailgate::base::LogLevel::Info,
        "control",
        std::format("advertising endpoint {} on {}", localEndpoint, underlayInterface));
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
    hostedConnections.UpdateNetworkMap(config);
    if (tailgate::serve::IsEnabled(funnel))
    {
        tailgate::base::Log(tailgate::base::LogLevel::Info,
                            "control",
                            "node capabilities=" + config.CapabilitySummary());
        if (!config.HasCapability("https") || !config.HasCapability("funnel"))
        {
            const tailgate::control::client::FeatureEnablement enablement =
                control.QueryFeature("funnel");
            if (!enablement.Complete)
            {
                throw std::runtime_error(std::format("{}\ncapabilities={}",
                                                     FeatureEnablementSummary(enablement),
                                                     config.CapabilitySummary()));
            }
            config = control.RequestNetworkMap();
            tailgate::base::Log(tailgate::base::LogLevel::Info,
                                "control",
                                "node capabilities after Funnel enablement=" +
                                    config.CapabilitySummary());
        }
        if (!config.HasCapability("https"))
        {
            throw std::runtime_error("Funnel not available; HTTPS capability is not enabled; "
                                     "capabilities=" +
                                     config.CapabilitySummary());
        }
        if (!config.HasCapability("funnel"))
        {
            throw std::runtime_error("Funnel not available; node does not have funnel capability; "
                                     "capabilities=" +
                                     config.CapabilitySummary());
        }
        if (!config.AllowsFunnelPort(funnel.Port))
        {
            throw std::runtime_error(
                std::format("Funnel not available; port {} is not allowed by control; "
                            "capabilities={}",
                            funnel.Port,
                            config.CapabilitySummary()));
        }
    }
    std::string funnelCertificatePem;
    std::string funnelPrivateKeyPem;
    if (tailgate::serve::IsEnabled(funnel))
    {
        std::string certificateDomain = config.SelfName();
        while (!certificateDomain.empty() && certificateDomain.back() == '.')
        {
            certificateDomain.pop_back();
        }
        if (std::find(config.CertDomains().begin(),
                      config.CertDomains().end(),
                      certificateDomain) == config.CertDomains().end())
        {
            throw std::runtime_error("control did not authorize an HTTPS certificate for " +
                                     certificateDomain);
        }
        constexpr std::chrono::hours RenewalWindow = std::chrono::hours(24 * 30);
        tailgate::crypto::Certificate& crypto =
            networkInjector.create<tailgate::crypto::Certificate&>();
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
            tailgate::net::http::Client& http =
                networkInjector.create<tailgate::net::http::Client&>();
            ControlDnsPublisher publisher(control);
            tailgate::serve::acme::AcmeClient acme(http, crypto, publisher);
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
    int derpRegion = config.DerpRegion();
    std::string derpHost = config.DerpHost();
    if (!exitNode.empty())
    {
        const auto selectedExitNode = config.FindExitNode(exitNode, true);
        if (!selectedExitNode)
        {
            throw std::runtime_error("exit node was not found in the network map: " + exitNode);
        }
        const tailgate::types::netmap::PeerConfig& peer = config.Peers()[*selectedExitNode];
        if (peer.DerpRegion() == 0 || peer.DerpHost().empty())
        {
            throw std::runtime_error("exit node has no usable DERP region: " + exitNode);
        }
        derpRegion = peer.DerpRegion();
        derpHost = peer.DerpHost();
    }
    if (derpRegion != 0 && !derpHost.empty())
    {
        try
        {
            const tailgate::net::Endpoint stunServer = ResolveIpv4UdpEndpoint(
                config.StunHost().empty() ? derpHost : config.StunHost(), config.StunPort());
            if (std::optional<tailgate::net::Endpoint> stunEndpoint =
                    session.DiscoverEndpoint(stunServer, StunResponseTimeout))
            {
                advertisedEndpoints.insert(
                    advertisedEndpoints.begin(),
                    tailgate::control::client::MapEndpoint{
                        .AddressPort = stunEndpoint->ToString(),
                        .Type = tailgate::control::client::EndpointType::Stun});
                control.SetEndpoints(advertisedEndpoints);
                tailgate::base::Log(tailgate::base::LogLevel::Info,
                                    "control",
                                    std::format("advertising STUN endpoint {} via {}",
                                                stunEndpoint->ToString(),
                                                derpHost));
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
    control.StartStreaming();
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
    const auto handleUpdate =
        [&hostedConnections](const tailgate::types::netmap::NetworkConfig& next)
    {
        hostedConnections.UpdateNetworkMap(next);
    };
    tailgate::linux_frontend::RunTunnel(nodePrivateKey,
                                        control.NodePublicKey(),
                                        control.DiscoPrivateKey(),
                                        config.SelfAddress(),
                                        config.FirstIpv6Address(),
                                        config.SelfName(),
                                        config.MagicDnsDomain().empty() ? config.Domain()
                                                                        : config.MagicDnsDomain(),
                                        config.DnsResolver(),
                                        config.DnsDomains(),
                                        config.DnsDefaultResolvers(),
                                        config.DnsRoutes(),
                                        config.Peers(),
                                        derpRegion,
                                        derpHost,
                                        exitNode,
                                        acceptDns,
                                        funnel,
                                        funnelCertificatePem,
                                        funnelPrivateKeyPem,
                                        std::move(ownedControl),
                                        eventRegistry,
                                        engine,
                                        session,
                                        connection,
                                        derpConnectionFactory,
                                        hostedConnections,
                                        status,
                                        readyFd,
                                        true,
                                        true,
                                        false,
                                        -1,
                                        handleUpdate,
                                        {});
}

} // namespace

namespace tailgate::linux_frontend
{

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
                         DaemonStatus& status,
                         int& readyFd,
                         const std::string& followupUrl,
                         Registration& registration,
                         const std::string& reauthorizationKey)
{
    RunConnectionImpl(authKey,
                      std::move(host),
                      machineKey,
                      nodePrivateKey,
                      discoPrivateKey,
                      acceptDns,
                      exitNode,
                      funnelPort,
                      funnelLocalPort,
                      exposePort,
                      status,
                      readyFd,
                      followupUrl,
                      registration,
                      reauthorizationKey);
}

} // namespace tailgate::linux_frontend
