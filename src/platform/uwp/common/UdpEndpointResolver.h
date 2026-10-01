#pragma once

#include <stop_token>
#include <string>

#include <tailgate/net/Endpoint.h>

namespace tailgate::uwp
{

// Bootstrap lookup, before installing VPN routes. The selected UDP transport
// still determines the adapter used to send to the returned remote endpoint.
class UdpEndpointResolver final
{
public:
    [[nodiscard]] tailgate::net::Endpoint
    Resolve(const std::string& host, std::uint16_t port, std::stop_token cancellation) const;
};

} // namespace tailgate::uwp
