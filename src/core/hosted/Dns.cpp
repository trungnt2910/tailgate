#include "tailgate/hosted/Dns.h"

#include <optional>
#include <utility>

#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>

namespace tailgate::hosted
{

DnsResult Dns::ProcessQuery(const std::vector<std::uint8_t>& packet,
                            const tailgate::types::netmap::NetworkConfig& network) const
{
    const std::optional<tailgate::net::packet::Ipv4UdpDatagram> query =
        tailgate::net::packet::Ipv4UdpDatagram::Parse(packet);
    if (!query || query->Destination() != tailgate::net::dns::MagicDnsIpv4Address ||
        query->DestinationPort() != tailgate::net::dns::DnsPort)
    {
        return {};
    }
    const std::optional<tailgate::net::Ipv4Address> self =
        tailgate::net::Ipv4Address::TryParse(network.SelfAddress());
    if (!self || query->Source() != self->HostOrder())
    {
        m_logger.LogWarning("dropping Tailnet DNS query from invalid source");
        return DnsResult{
            .Status = DnsStatus::Invalid,
            .RemoteFrame = std::nullopt,
            .LocalPacket = std::nullopt,
            .Name = std::nullopt,
        };
    }
    const std::optional<std::string> name = tailgate::net::dns::DnsQuery::Name(query->Payload());
    m_logger.LogInfo("sent hosted Tailnet DNS query name={}", name.value_or("<invalid>"));
    return DnsResult{
        .Status = DnsStatus::Complete,
        .RemoteFrame = Frame(MessageType::TailnetDnsQuery, packet),
        .LocalPacket = std::nullopt,
        .Name = name,
    };
}

DnsResult Dns::ProcessResponse(const Frame& frame,
                               const tailgate::types::netmap::NetworkConfig& network) const
{
    if (frame.Type() != MessageType::TailnetDnsResponse)
    {
        return {};
    }
    const std::optional<tailgate::net::packet::Ipv4UdpDatagram> response =
        tailgate::net::packet::Ipv4UdpDatagram::Parse(frame.Payload());
    const std::optional<tailgate::net::Ipv4Address> self =
        tailgate::net::Ipv4Address::TryParse(network.SelfAddress());
    if (!response || !self || response->Source() != tailgate::net::dns::MagicDnsIpv4Address ||
        response->Destination() != self->HostOrder() ||
        response->SourcePort() != tailgate::net::dns::DnsPort)
    {
        m_logger.LogWarning("hosted Tailnet DNS response failed validation");
        return DnsResult{
            .Status = DnsStatus::Invalid,
            .RemoteFrame = std::nullopt,
            .LocalPacket = std::nullopt,
            .Name = std::nullopt,
        };
    }
    const std::optional<std::string> name = tailgate::net::dns::DnsQuery::Name(response->Payload());
    m_logger.LogInfo("received hosted Tailnet DNS response name={}",
                     name.value_or("<unavailable>"));
    return DnsResult{
        .Status = DnsStatus::Complete,
        .RemoteFrame = std::nullopt,
        .LocalPacket = frame.Payload(),
        .Name = name,
    };
}

} // namespace tailgate::hosted
