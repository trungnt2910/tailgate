#include "tailgate/types/netmap/Capabilities.h"

#include <algorithm>
#include <set>

#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::types::netmap
{
namespace
{

std::vector<net::IpAddress> Addresses(const std::vector<std::string>& values,
                                      const std::string& fallback)
{
    std::vector<net::IpAddress> result;
    for (const auto& value : values)
    {
        if (const auto address = net::IpAddress::TryParse(value))
        {
            result.push_back(*address);
        }
    }
    if (result.empty())
    {
        if (const auto address = net::IpAddress::TryParse(fallback))
        {
            result.push_back(*address);
        }
    }
    return result;
}

bool Matches(const std::vector<net::IpRange>& ranges, const net::IpAddress& address)
{
    return std::ranges::any_of(ranges,
                               [&](const auto& range)
                               {
                                   return range.Contains(address);
                               });
}

} // namespace

void RefreshPeerCapabilities(NetworkConfig& configuration)
{
    const auto destinations = Addresses(configuration.SelfAddresses(), configuration.SelfAddress());
    auto peers = configuration.Peers();
    for (auto& peer : peers)
    {
        const auto sources = Addresses(peer.Addresses(), peer.Address());
        std::set<std::string> names;
        for (const auto& [key, grants] : configuration.CapabilityFilters())
        {
            (void)key;
            for (const auto& grant : grants)
            {
                const bool applies =
                    std::ranges::any_of(sources,
                                        [&](const auto& source)
                                        {
                                            const auto destination = std::ranges::find_if(
                                                destinations,
                                                [&](const auto& value)
                                                {
                                                    return value.Family() == source.Family();
                                                });
                                            return destination != destinations.end() &&
                                                   Matches(grant.Sources, source) &&
                                                   Matches(grant.Destinations, *destination);
                                        });
                if (applies)
                {
                    names.insert(grant.Names.begin(), grant.Names.end());
                }
            }
        }
        peer.Capabilities(std::vector<std::string>(names.begin(), names.end()));
    }
    configuration.Peers(std::move(peers));
}

} // namespace tailgate::types::netmap
