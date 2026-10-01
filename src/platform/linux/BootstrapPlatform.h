#pragma once

#include <tailgate/ipn/ipnlocal/NodeBootstrap.h>

#include "HostedConnectionRegistry.h"
#include "Registration.h"

namespace tailgate::linux_frontend
{

class BootstrapPlatform final : public tailgate::ipn::ipnlocal::BootstrapPlatform
{
public:
    BootstrapPlatform(Registration& registration, HostedConnectionRegistry& hosted);
    [[nodiscard]] tailgate::net::Endpoint ResolveUdp(const std::string& host,
                                                     std::uint16_t port) override;
    [[nodiscard]] std::optional<tailgate::serve::acme::CertificateState> ReadCertificate() override;
    void WriteCertificate(const tailgate::serve::acme::CertificateState& state) override;
    void Registered(const tailgate::types::netmap::NetworkConfig& network) override;

private:
    Registration& m_registration;
    HostedConnectionRegistry& m_hosted;
};

} // namespace tailgate::linux_frontend
