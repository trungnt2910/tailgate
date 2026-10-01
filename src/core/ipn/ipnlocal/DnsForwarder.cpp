#include "tailgate/ipn/ipnlocal/DnsForwarder.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <utility>

#include <tailgate/net/dns/ResolverSelection.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>

namespace tailgate::ipn::ipnlocal
{
namespace
{

constexpr auto PendingTimeout = std::chrono::seconds(10);
constexpr std::size_t MaximumPending = 4096;
constexpr std::size_t IdSize = 2;

std::uint16_t Id(const std::vector<std::uint8_t>& payload)
{
    return (static_cast<std::uint16_t>(payload[0]) << 8U) | payload[1];
}

void SetId(std::vector<std::uint8_t>& payload, std::uint16_t id)
{
    payload[0] = static_cast<std::uint8_t>(id >> 8U);
    payload[1] = static_cast<std::uint8_t>(id);
}

} // namespace

DnsForwarder::DnsForwarder(crypto::Random& random) : m_random(random)
{
}

DnsForward DnsForwarder::Begin(net::Endpoint client,
                               std::vector<std::uint8_t> payload,
                               const NetworkPolicy& policy,
                               const std::vector<std::string>& originalResolvers,
                               TimePoint now)
{
    if (payload.size() < IdSize)
    {
        return {};
    }
    const auto& network = policy.Network();
    const auto& defaults =
        network.DnsDefaultResolvers().empty() ? originalResolvers : network.DnsDefaultResolvers();
    const auto selected =
        net::dns::SelectResolver(payload, network.DnsResolver(), network.DnsRoutes(), defaults);
    const auto resolver = selected ? net::Ipv4Address::TryParse(selected->Address) : std::nullopt;
    const auto self = net::Ipv4Address::TryParse(network.SelfAddress());
    if (!resolver || !self)
    {
        DnsForward result;
        result.Status = DnsForwardStatus::UnsupportedResolver;
        return result;
    }
    const auto originalId = Id(payload);
    Expire(now);
    std::erase_if(m_pending,
                  [&](const Pending& pending)
                  {
                      const bool replaced =
                          pending.Client == client && pending.OriginalId == originalId;
                      if (replaced)
                      {
                          m_wireIds.reset(pending.WireId);
                      }
                      return replaced;
                  });
    if (m_pending.size() >= MaximumPending)
    {
        DnsForward result;
        result.Status = DnsForwardStatus::Full;
        return result;
    }
    std::array<std::uint8_t, IdSize> randomId{};
    m_random.Fill(randomId);
    std::uint16_t wireId = (static_cast<std::uint16_t>(randomId[0]) << 8U) | randomId[1];
    // At most MaximumPending occupied slots can precede a free ID.
    while (m_wireIds.test(wireId))
    {
        ++wireId;
    }
    SetId(payload, wireId);
    const bool tunneled = resolver->HostOrder() == net::dns::MagicDnsIpv4Address ||
                          network.FindRoute(resolver->HostOrder(), policy.ExitPeer()).has_value();
    DnsForward result;
    result.Status = DnsForwardStatus::Ready;
    result.Resolver = net::Endpoint(*resolver, net::dns::DnsPort);
    result.Payload = std::move(payload);
    if (tunneled)
    {
        result.TunnelPacket = net::packet::Ipv4UdpDatagram::Build(self->HostOrder(),
                                                                  resolver->HostOrder(),
                                                                  client.Port(),
                                                                  net::dns::DnsPort,
                                                                  result.Payload);
    }
    m_pending.push_back(Pending{.Client = client,
                                .Self = *self,
                                .Resolver = *resolver,
                                .OriginalId = originalId,
                                .WireId = wireId,
                                .Tunneled = tunneled,
                                .Started = now});
    m_wireIds.set(wireId);
    return result;
}

std::optional<DnsReply> DnsForwarder::CompletePacket(const std::vector<std::uint8_t>& packet)
{
    const auto datagram = net::packet::Ipv4UdpDatagram::Parse(packet);
    if (!datagram || datagram->SourcePort() != net::dns::DnsPort ||
        datagram->Payload().size() < IdSize)
    {
        return std::nullopt;
    }
    const auto found =
        std::ranges::find_if(m_pending,
                             [&](const Pending& pending)
                             {
                                 return pending.Tunneled &&
                                        pending.Resolver.HostOrder() == datagram->Source() &&
                                        pending.Self.HostOrder() == datagram->Destination() &&
                                        pending.Client.Port() == datagram->DestinationPort() &&
                                        pending.WireId == Id(datagram->Payload());
                             });
    return found == m_pending.end() ? std::nullopt
                                    : std::optional(Finish(found, datagram->Payload()));
}

std::optional<DnsReply> DnsForwarder::CompleteDatagram(net::Endpoint source,
                                                       std::vector<std::uint8_t> payload)
{
    if (source.Port() != net::dns::DnsPort || payload.size() < IdSize)
    {
        return std::nullopt;
    }
    const auto found = std::ranges::find_if(m_pending,
                                            [&](const Pending& pending)
                                            {
                                                return !pending.Tunneled &&
                                                       pending.Resolver == source.Address() &&
                                                       pending.WireId == Id(payload);
                                            });
    return found == m_pending.end() ? std::nullopt
                                    : std::optional(Finish(found, std::move(payload)));
}

DnsReply DnsForwarder::Finish(std::vector<Pending>::iterator pending,
                              std::vector<std::uint8_t> payload)
{
    SetId(payload, pending->OriginalId);
    DnsReply reply{.Client = pending->Client, .Payload = std::move(payload)};
    m_wireIds.reset(pending->WireId);
    m_pending.erase(pending);
    return reply;
}

void DnsForwarder::Reset() noexcept
{
    m_pending.clear();
    m_wireIds.reset();
}

void DnsForwarder::Expire(TimePoint now)
{
    std::erase_if(m_pending,
                  [this, now](const Pending& pending)
                  {
                      const bool expired = now - pending.Started >= PendingTimeout;
                      if (expired)
                      {
                          m_wireIds.reset(pending.WireId);
                      }
                      return expired;
                  });
}

std::optional<DnsForwarder::TimePoint> DnsForwarder::NextDeadline() const
{
    const auto first = std::ranges::min_element(m_pending, {}, &Pending::Started);
    return first == m_pending.end() ? std::nullopt : std::optional(first->Started + PendingTimeout);
}

} // namespace tailgate::ipn::ipnlocal
