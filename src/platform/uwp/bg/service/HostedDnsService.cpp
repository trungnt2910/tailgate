#include "HostedDnsService.h"

#include <stdexcept>
#include <utility>

namespace tailgate::uwp::bg::service
{

HostedDnsService::HostedDnsService(manager::DataPlaneManager& dataPlaneManager,
                                   tailgate::hosted::Dns& dns)
    : m_dns(dns)
{
    dataPlaneManager.Register(*this);
}

void HostedDnsService::Start(SessionGeneration)
{
}

void HostedDnsService::Stop()
{
}

void HostedDnsService::Reset()
{
}

void HostedDnsService::Encapsulate(EncapsulationContext& context)
{
    tailgate::hosted::DnsResult result =
        m_dns.ProcessQuery(context.Original, context.Client.Network());
    if (result.Status != tailgate::hosted::DnsStatus::Complete)
    {
        return;
    }
    AppendRelayFrame(context.RemoteOutput, *result.RemoteFrame);
}

void HostedDnsService::Decapsulate(DecapsulationContext& context)
{
    tailgate::hosted::DnsResult result =
        m_dns.ProcessResponse(context.Message, context.Client.Network());
    if (result.Status == tailgate::hosted::DnsStatus::Unhandled)
    {
        return;
    }
    if (result.Status == tailgate::hosted::DnsStatus::Invalid)
    {
        throw std::runtime_error("Tailgate relay returned an invalid DNS response");
    }
    context.LocalOutput.push_back(std::move(*result.LocalPacket));
}

void HostedDnsService::FlushLocal(std::vector<std::vector<std::uint8_t>>&)
{
}

} // namespace tailgate::uwp::bg::service
