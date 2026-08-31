#pragma once

#include <optional>
#include <string>
#include <vector>

#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::net::dns
{

struct ResolverSelection
{
    std::string Address;
    bool RouteMatched = false;
};

[[nodiscard]] std::optional<ResolverSelection>
SelectResolver(const std::vector<std::uint8_t>& query,
               const std::string& primaryResolver,
               const std::vector<tailgate::types::netmap::NetworkConfig::DnsRoute>& routes,
               const std::vector<std::string>& defaultResolvers);

} // namespace tailgate::net::dns
