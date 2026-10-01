#include "tailgate/ipn/ipnlocal/NodeBootstrap.h"

#include <algorithm>
#include <chrono>
#include <format>
#include <utility>

#include <tailgate/base/Logging.h>
#include <tailgate/ipn/ipnlocal/NodeError.h>
#include <tailgate/serve/acme/Client.h>

namespace
{

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

} // namespace

namespace tailgate::ipn::ipnlocal
{

NodeBootstrap::NodeBootstrap(control::client::Connection& control,
                             wgengine::Session& session,
                             net::http::Client& http,
                             crypto::Certificate& crypto,
                             BootstrapPlatform& platform)
    : m_control(control), m_session(session), m_http(http), m_crypto(crypto), m_platform(platform)
{
}

void NodeBootstrap::ConfigureHost(const serve::FunnelConfig& funnel,
                                  control::client::HostInfo& host)
{
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
}

HostedBootstrapResult
NodeBootstrap::RegisterHosted(control::client::Connection& control,
                              const std::string& authKey,
                              const control::client::RegistrationOptions& options,
                              const std::string& exitNode)
{
    auto registration = control.RegisterUntilAuthorized(authKey, options);
    if (!registration.Network)
    {
        throw NodeError(NodeFailure::MissingNetworkMap);
    }
    auto network = std::move(*registration.Network);
    control.UpdateHostInfo(network.DerpRegion());
    if (!registration.NetworkMapStreaming)
    {
        control.SetPreferredDerp(network.DerpRegion());
    }
    const auto effectiveExit = network.FindExitNode(exitNode, true) ? exitNode : std::string{};
    return {.Network = std::move(network), .ExitNode = effectiveExit};
}

std::vector<control::client::MapEndpoint>
NodeBootstrap::DiscoverEndpoints(wgengine::Session& session,
                                 const net::Endpoint& localEndpoint,
                                 const std::optional<net::Endpoint>& stunServer)
{
    std::vector<control::client::MapEndpoint> endpoints{
        {.AddressPort = localEndpoint.ToString(), .Type = control::client::EndpointType::Local}};
    if (stunServer)
    {
        if (const auto discovered = session.DiscoverEndpoint(*stunServer, StunResponseTimeout))
        {
            endpoints.insert(endpoints.begin(),
                             {.AddressPort = discovered->ToString(),
                              .Type = control::client::EndpointType::Stun});
        }
    }
    return endpoints;
}

BootstrapResult
NodeBootstrap::Start(const std::string& authKey,
                     const control::client::RegistrationOptions& registrationOptions,
                     const net::Endpoint& localEndpoint,
                     const serve::FunnelConfig& funnel,
                     const std::string& exitNode)
{
    auto& control = m_control;
    std::vector<tailgate::control::client::MapEndpoint> advertisedEndpoints{
        tailgate::control::client::MapEndpoint{.AddressPort = localEndpoint.ToString(),
                                               .Type =
                                                   tailgate::control::client::EndpointType::Local}};
    control.SetEndpoints(advertisedEndpoints);
    tailgate::control::client::RegistrationResult registration =
        control.RegisterUntilAuthorized(authKey, registrationOptions);
    if (!registration.Network)
    {
        tailgate::base::Log(tailgate::base::LogLevel::Error,
                            "control",
                            "control registration completed without a network map");
        throw NodeError(NodeFailure::MissingNetworkMap);
    }
    tailgate::types::netmap::NetworkConfig config = std::move(*registration.Network);
    m_platform.Registered(config);
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
                tailgate::base::Log(tailgate::base::LogLevel::Error,
                                    "control",
                                    std::format("{}\ncapabilities={}",
                                                FeatureEnablementSummary(enablement),
                                                config.CapabilitySummary()));
                throw NodeError(NodeFailure::FunnelEnablementRequired);
            }
            config = control.RequestNetworkMap();
            tailgate::base::Log(tailgate::base::LogLevel::Info,
                                "control",
                                "node capabilities after Funnel enablement=" +
                                    config.CapabilitySummary());
        }
        if (!config.HasCapability("https"))
        {
            tailgate::base::Log(tailgate::base::LogLevel::Error,
                                "control",
                                "Funnel not available; HTTPS capability is not enabled; "
                                "capabilities=" +
                                    config.CapabilitySummary());
            throw NodeError(NodeFailure::HttpsUnavailable);
        }
        if (!config.HasCapability("funnel"))
        {
            tailgate::base::Log(tailgate::base::LogLevel::Error,
                                "control",
                                "Funnel not available; node does not have funnel capability; "
                                "capabilities=" +
                                    config.CapabilitySummary());
            throw NodeError(NodeFailure::FunnelUnavailable);
        }
        if (!config.AllowsFunnelPort(funnel.Port))
        {
            tailgate::base::Log(
                tailgate::base::LogLevel::Error,
                "control",
                std::format("Funnel not available; port {} is not allowed by control; "
                            "capabilities={}",
                            funnel.Port,
                            config.CapabilitySummary()));
            throw NodeError(NodeFailure::FunnelPortDenied);
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
            tailgate::base::Log(tailgate::base::LogLevel::Error,
                                "control",
                                "control did not authorize an HTTPS certificate for " +
                                    certificateDomain);
            throw NodeError(NodeFailure::CertificateDenied);
        }
        constexpr std::chrono::hours RenewalWindow = std::chrono::hours(24 * 30);
        auto& crypto = m_crypto;
        std::optional<serve::acme::CertificateState> cached = m_platform.ReadCertificate();
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
            auto& http = m_http;
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
            m_platform.WriteCertificate(
                serve::acme::CertificateState{.Domain = certificateDomain,
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
            tailgate::base::Log(tailgate::base::LogLevel::Error,
                                "control",
                                "exit node was not found in the network map: " + exitNode);
            throw NodeError(NodeFailure::ExitNodeMissing);
        }
        const tailgate::types::netmap::PeerConfig& peer = config.Peers()[*selectedExitNode];
        if (peer.DerpRegion() == 0 || peer.DerpHost().empty())
        {
            tailgate::base::Log(tailgate::base::LogLevel::Error,
                                "control",
                                "exit node has no usable DERP region: " + exitNode);
            throw NodeError(NodeFailure::ExitNodeDerpMissing);
        }
        derpRegion = peer.DerpRegion();
        derpHost = peer.DerpHost();
    }
    std::optional<net::Endpoint> stunServer;
    if (derpRegion != 0 && !derpHost.empty())
    {
        try
        {
            stunServer = m_platform.ResolveUdp(
                config.StunHost().empty() ? derpHost : config.StunHost(), config.StunPort());
            advertisedEndpoints = DiscoverEndpoints(m_session, localEndpoint, stunServer);
            if (advertisedEndpoints.size() > 1)
            {
                control.SetEndpoints(advertisedEndpoints);
                tailgate::base::Log(tailgate::base::LogLevel::Info,
                                    "control",
                                    std::format("advertising STUN endpoint {} via {}",
                                                advertisedEndpoints.front().AddressPort,
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
    return BootstrapResult{.Network = std::move(config),
                           .DerpRegion = derpRegion,
                           .DerpHost = std::move(derpHost),
                           .CertificatePem = std::move(funnelCertificatePem),
                           .PrivateKeyPem = std::move(funnelPrivateKeyPem),
                           .StunServer = stunServer};
}

} // namespace tailgate::ipn::ipnlocal
