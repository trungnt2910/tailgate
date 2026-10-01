#pragma once

#include <tailgate/net/netmon/Resolver.h>

namespace tailgate::linux_frontend
{

class UnderlayResolver final : public net::netmon::Resolver
{
public:
    [[nodiscard]] net::Endpoint Resolve(const std::string& host,
                                        std::uint16_t port,
                                        const std::optional<std::string>& networkInterface,
                                        std::stop_token cancellation) override;
};

} // namespace tailgate::linux_frontend
