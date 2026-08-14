#include "HostedDnsService.h"

#include <optional>
#include <string>

#include <tailgate/hosted/Protocol.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>

namespace tailgate::uwp::bg::service
{

HostedDnsService::HostedDnsService(manager::DataPlaneManager& dataPlaneManager)
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
    const std::optional<tailgate::net::packet::Ipv4UdpDatagram> query =
        tailgate::net::packet::ParseIpv4UdpDatagram(context.Original);
    if (!query || query->Destination != tailgate::net::dns::MagicDnsIpv4Address ||
        query->DestinationPort != tailgate::net::dns::DnsPort)
    {
        return;
    }
    const std::optional<std::uint32_t> self =
        tailgate::net::packet::ParseIpv4(context.Config.SelfAddress);
    if (!self || query->Source != *self)
    {
        m_logger.LogWarning("dropping Tailnet DNS query from invalid source");
        return;
    }
    const std::optional<std::string> name = tailgate::net::dns::DnsQueryName(query->Payload);
    AppendRelayFrame(context.RemoteOutput,
                     tailgate::hosted::Frame{
                         .Type = tailgate::hosted::MessageType::TailnetDnsQuery,
                         .Payload = context.Original,
                     });
    m_logger.LogInfo("sent hosted Tailnet DNS query name={}", name.value_or("<invalid>"));
}

void HostedDnsService::Decapsulate(DecapsulationContext& context)
{
    if (context.Message.Type != tailgate::hosted::MessageType::TailnetDnsResponse)
    {
        return;
    }
    const std::optional<tailgate::net::packet::Ipv4UdpDatagram> response =
        tailgate::net::packet::ParseIpv4UdpDatagram(context.Message.Payload);
    const std::optional<std::uint32_t> self =
        tailgate::net::packet::ParseIpv4(context.Config.SelfAddress);
    if (!response || !self || response->Source != tailgate::net::dns::MagicDnsIpv4Address ||
        response->Destination != *self || response->SourcePort != tailgate::net::dns::DnsPort)
    {
        throw std::runtime_error("Tailgate relay returned an invalid DNS response");
    }
    const std::optional<std::string> name = tailgate::net::dns::DnsQueryName(response->Payload);
    context.LocalOutput.push_back(context.Message.Payload);
    m_logger.LogInfo("injected hosted Tailnet DNS response name={}",
                     name.value_or("<unavailable>"));
}

void HostedDnsService::FlushLocal(std::vector<std::vector<std::uint8_t>>&)
{
}

} // namespace tailgate::uwp::bg::service
