#include "UnderlayResolver.h"

#include <tailgate/net/dns/Dns.h>

#include "ThreadApartment.h"

namespace tailgate::uwp
{

UnderlayResolver::UnderlayResolver(tailgate::types::nettype::TcpSocketFactory& sockets)
    : m_sockets(sockets)
{
}

tailgate::net::Endpoint
UnderlayResolver::Resolve(const std::string& host,
                          std::uint16_t port,
                          const std::optional<std::string>& networkInterface,
                          std::stop_token cancellation)
{
    ThreadApartment::Ensure();
    if (const auto address = tailgate::net::Ipv4Address::TryParse(host))
    {
        return tailgate::net::Endpoint(*address, port);
    }
    // Host DNS can point at Quad100 while the VPN owns the default route. Bootstrap
    // discovery must use an explicit underlay, just like relay bootstrap DNS.
    constexpr auto ResolverAddress = "1.1.1.1";
    constexpr auto ResolverTlsName = "cloudflare-dns.com";
    constexpr auto DnsOverTlsPort = "853";
    auto stream = m_sockets.OpenTcpSocket({.ConnectAddress = ResolverAddress,
                                           .Service = DnsOverTlsPort,
                                           .NetworkInterface = networkInterface,
                                           .TlsServerName = ResolverTlsName,
                                           .IoTimeout = std::chrono::seconds(15),
                                           .ConnectTimeout = std::nullopt,
                                           .ReadinessToken = {},
                                           .AllowTls13 = false,
                                           .NonBlockingAfterConnect = false,
                                           .Cancellation = cancellation});
    constexpr std::size_t MaximumCanonicalQueries = 8;
    const auto target =
        tailgate::net::dns::ResolveDnsOverTlsTarget(*stream, host, 0, MaximumCanonicalQueries);
    return tailgate::net::Endpoint(tailgate::net::Ipv4Address::Parse(target.ConnectAddress), port);
}

} // namespace tailgate::uwp
