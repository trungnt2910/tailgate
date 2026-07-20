#include "HostedDnsService.h"

#include <optional>
#include <string>

#include <tailgate/network/Dns.h>
#include <tailgate/network/Ipv4.h>
#include <tailgate/network/TailnetDns.h>
#include <tailgate/relay/RelayProtocol.h>

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
    const std::optional<network::Ipv4UdpDatagram> query =
        network::ParseIpv4UdpDatagram(context.Original);
    if (!query || query->Destination != network::MagicDnsIpv4Address ||
        query->DestinationPort != network::DnsPort)
    {
        return;
    }
    const std::optional<std::uint32_t> self = network::ParseIpv4(context.Config.SelfAddress);
    if (!self || query->Source != *self)
    {
        m_logger.LogWarning("dropping Tailnet DNS query from invalid source");
        return;
    }
    const std::optional<std::string> name = network::DnsQueryName(query->Payload);
    AppendRelayFrame(context.RemoteOutput,
                     relay::Frame{
                         .Type = relay::MessageType::TailnetDnsQuery,
                         .Payload = context.Original,
                     });
    m_logger.LogInfo("sent hosted Tailnet DNS query name={}", name.value_or("<invalid>"));
}

void HostedDnsService::Decapsulate(DecapsulationContext& context)
{
    if (context.Message.Type != relay::MessageType::TailnetDnsResponse)
    {
        return;
    }
    const std::optional<network::Ipv4UdpDatagram> response =
        network::ParseIpv4UdpDatagram(context.Message.Payload);
    const std::optional<std::uint32_t> self = network::ParseIpv4(context.Config.SelfAddress);
    if (!response || !self || response->Source != network::MagicDnsIpv4Address ||
        response->Destination != *self || response->SourcePort != network::DnsPort)
    {
        throw std::runtime_error("Tailgate relay returned an invalid DNS response");
    }
    const std::optional<std::string> name = network::DnsQueryName(response->Payload);
    context.LocalOutput.push_back(context.Message.Payload);
    m_logger.LogInfo("injected hosted Tailnet DNS response name={}",
                     name.value_or("<unavailable>"));
}

void HostedDnsService::FlushLocal(std::vector<std::vector<std::uint8_t>>&)
{
}

} // namespace tailgate::uwp::bg::service
