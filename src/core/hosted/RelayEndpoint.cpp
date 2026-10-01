#include "tailgate/hosted/RelayEndpoint.h"

#include <stdexcept>

#include <boost/url/parse.hpp>

#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/dns/Dns.h>

namespace tailgate::hosted
{

RelayEndpoint RelayEndpoint::Parse(const std::string& text)
{
    const auto url = boost::urls::parse_uri(text);
    if (!url || url->scheme() != "https" || url->host().empty() || url->has_userinfo() ||
        (url->has_port() && url->port().empty()))
    {
        throw std::invalid_argument("relay endpoint must be an HTTPS URL without credentials");
    }
    return {.Host = url->host(),
            .ConnectAddress = {},
            .Port = url->has_port() ? std::string(url->port()) : "443"};
}

void RelayEndpoint::Resolve(types::nettype::TcpSocketFactory& sockets,
                            const std::optional<std::string>& networkInterface,
                            std::size_t addressAttempt,
                            std::stop_token cancellation,
                            bool allowTls13)
{
    if (net::Ipv4Address::TryParse(Host))
    {
        ConnectAddress = Host;
        return;
    }
    constexpr auto ResolverAddress = "1.1.1.1";
    constexpr auto ResolverTlsName = "cloudflare-dns.com";
    constexpr auto DnsOverTlsPort = "853";
    constexpr auto Timeout = std::chrono::seconds(15);
    constexpr std::size_t MaximumCanonicalQueries = 8;
    auto stream = sockets.OpenTcpSocket({.ConnectAddress = ResolverAddress,
                                         .Service = DnsOverTlsPort,
                                         .NetworkInterface = networkInterface,
                                         .TlsServerName = ResolverTlsName,
                                         .IoTimeout = Timeout,
                                         .ConnectTimeout = std::nullopt,
                                         .ReadinessToken = {},
                                         .AllowTls13 = allowTls13,
                                         .NonBlockingAfterConnect = false,
                                         .Cancellation = cancellation});
    const auto target =
        net::dns::ResolveDnsOverTlsTarget(*stream, Host, addressAttempt, MaximumCanonicalQueries);
    Host = target.ValidationName;
    ConnectAddress = target.ConnectAddress;
}

} // namespace tailgate::hosted
