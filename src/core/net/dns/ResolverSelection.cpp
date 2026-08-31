#include "tailgate/net/dns/ResolverSelection.h"

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include <tailgate/net/dns/Dns.h>

namespace tailgate::net::dns
{

std::optional<ResolverSelection>
SelectResolver(const std::vector<std::uint8_t>& query,
               const std::string& primaryResolver,
               const std::vector<tailgate::types::netmap::NetworkConfig::DnsRoute>& routes,
               const std::vector<std::string>& defaultResolvers)
{
    const std::optional<std::string> name = DnsQuery::Name(query);
    const std::vector<std::string>* selected = nullptr;
    std::size_t selectedSuffixLength = 0;
    for (const tailgate::types::netmap::NetworkConfig::DnsRoute& route : routes)
    {
        if (name && route.Suffix.size() >= selectedSuffixLength &&
            DnsNameHasSuffix(*name, route.Suffix))
        {
            selected = &route.Resolvers;
            selectedSuffixLength = route.Suffix.size();
        }
    }
    if (selected != nullptr)
    {
        const std::string address = selected->empty() ? primaryResolver : selected->front();
        if (address.empty())
        {
            return std::nullopt;
        }
        return ResolverSelection{
            .Address = address,
            .RouteMatched = true,
        };
    }
    const std::string address =
        defaultResolvers.empty() ? primaryResolver : defaultResolvers.front();
    if (address.empty())
    {
        return std::nullopt;
    }
    return ResolverSelection{
        .Address = address,
        .RouteMatched = false,
    };
}

} // namespace tailgate::net::dns
