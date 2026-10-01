#include "UnderlayResolver.h"

#include <system_error>

#include <arpa/inet.h>

#include "impl/ResolveTcp.h"

namespace tailgate::linux_frontend
{

net::Endpoint UnderlayResolver::Resolve(const std::string& host,
                                        std::uint16_t port,
                                        const std::optional<std::string>&,
                                        std::stop_token cancellation)
{
    // The system resolver may be localhost/Quad100. Do not bind that DNS query to
    // a physical adapter; only the resulting STUN socket uses the underlay.
    for (const auto& address :
         impl::ResolveTcp(host, std::to_string(port), std::chrono::seconds(10), cancellation))
    {
        if (address.Family == AF_INET)
        {
            const auto& ipv4 = reinterpret_cast<const sockaddr_in&>(address.Address);
            return net::Endpoint(net::Ipv4Address::FromHostOrder(ntohl(ipv4.sin_addr.s_addr)),
                                 port);
        }
    }
    throw std::system_error(std::make_error_code(std::errc::host_unreachable));
}

} // namespace tailgate::linux_frontend
