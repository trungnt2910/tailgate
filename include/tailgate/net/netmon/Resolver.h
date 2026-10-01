#pragma once

#include <optional>
#include <stop_token>
#include <string>

#include <tailgate/net/Endpoint.h>

namespace tailgate::net::netmon
{

class Resolver
{
public:
    virtual ~Resolver() = default;
    [[nodiscard]] virtual Endpoint Resolve(const std::string& host,
                                           std::uint16_t port,
                                           const std::optional<std::string>& networkInterface,
                                           std::stop_token cancellation) = 0;
};

} // namespace tailgate::net::netmon
