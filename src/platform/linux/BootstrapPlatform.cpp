#include "BootstrapPlatform.h"

#include "Network.h"
#include "State.h"

namespace tailgate::linux_frontend
{

BootstrapPlatform::BootstrapPlatform(Registration& registration, HostedConnectionRegistry& hosted)
    : m_registration(registration), m_hosted(hosted)
{
}

tailgate::net::Endpoint BootstrapPlatform::ResolveUdp(const std::string& host, std::uint16_t port)
{
    return ResolveIpv4UdpEndpoint(host, port);
}

std::optional<tailgate::serve::acme::CertificateState> BootstrapPlatform::ReadCertificate()
{
    return ReadAcmeState();
}

void BootstrapPlatform::WriteCertificate(const tailgate::serve::acme::CertificateState& state)
{
    WriteAcmeState(state);
}

void BootstrapPlatform::Registered(const tailgate::types::netmap::NetworkConfig& network)
{
    m_registration.Accepted();
    m_hosted.UpdateNetworkMap(network);
}

} // namespace tailgate::linux_frontend
