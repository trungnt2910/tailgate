#pragma once

#include <tailgate/control/client/Connection.h>
#include <tailgate/crypto/Certificate.h>
#include <tailgate/net/http/Client.h>
#include <tailgate/serve/FunnelConfig.h>
#include <tailgate/serve/acme/CertificateState.h>
#include <tailgate/wgengine/Session.h>

namespace tailgate::ipn::ipnlocal
{

class BootstrapPlatform
{
public:
    virtual ~BootstrapPlatform() = default;
    [[nodiscard]] virtual net::Endpoint ResolveUdp(const std::string& host, std::uint16_t port) = 0;
    [[nodiscard]] virtual std::optional<serve::acme::CertificateState> ReadCertificate() = 0;
    virtual void WriteCertificate(const serve::acme::CertificateState& state) = 0;
    virtual void Registered(const types::netmap::NetworkConfig& network) = 0;
};

struct BootstrapResult
{
    types::netmap::NetworkConfig Network;
    int DerpRegion = 0;
    std::string DerpHost;
    std::string CertificatePem;
    std::string PrivateKeyPem;
    std::optional<net::Endpoint> StunServer;
};

struct HostedBootstrapResult
{
    types::netmap::NetworkConfig Network;
    std::string ExitNode;
};

// Registration, DNS lookup and certificate issuance run on the bootstrap worker,
// never from a VPN packet callback. Streaming processing remains event driven.
class NodeBootstrap final
{
public:
    NodeBootstrap(control::client::Connection& control,
                  wgengine::Session& session,
                  net::http::Client& http,
                  crypto::Certificate& crypto,
                  BootstrapPlatform& platform);
    static void ConfigureHost(const serve::FunnelConfig& funnel, control::client::HostInfo& host);
    [[nodiscard]] static HostedBootstrapResult
    RegisterHosted(control::client::Connection& control,
                   const std::string& authKey,
                   const control::client::RegistrationOptions& registration,
                   const std::string& exitNode);
    [[nodiscard]] static std::vector<control::client::MapEndpoint>
    DiscoverEndpoints(wgengine::Session& session,
                      const net::Endpoint& localEndpoint,
                      const std::optional<net::Endpoint>& stunServer);
    [[nodiscard]] BootstrapResult Start(const std::string& authKey,
                                        const control::client::RegistrationOptions& registration,
                                        const net::Endpoint& localEndpoint,
                                        const serve::FunnelConfig& funnel,
                                        const std::string& exitNode);

private:
    control::client::Connection& m_control;
    wgengine::Session& m_session;
    net::http::Client& m_http;
    crypto::Certificate& m_crypto;
    BootstrapPlatform& m_platform;
};

} // namespace tailgate::ipn::ipnlocal
