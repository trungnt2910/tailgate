#include "ChannelPolicy.h"

#include <algorithm>
#include <cctype>
#include <cstddef>

#include <tailgate/wgengine/router/Config.h>

#include "common/VpnConstants.h"

namespace tailgate::uwp::bg::manager
{
namespace
{

constexpr std::size_t MaximumDnsNameLength = 253;
constexpr std::size_t MaximumDnsLabelLength = 63;

std::string NormalizeDnsName(std::string name)
{
    while (!name.empty() && name.back() == '.')
    {
        name.pop_back();
    }
    return name;
}

bool IsDnsNamespace(const std::string& name)
{
    const std::string normalized = NormalizeDnsName(name);
    if (normalized.empty() || normalized.size() > MaximumDnsNameLength)
    {
        return false;
    }
    std::size_t start = 0;
    while (start < normalized.size())
    {
        const std::size_t dot = normalized.find('.', start);
        const std::size_t end = dot == std::string::npos ? normalized.size() : dot;
        if (end == start || end - start > MaximumDnsLabelLength)
        {
            return false;
        }
        for (std::size_t index = start; index < end; ++index)
        {
            const unsigned char character = static_cast<unsigned char>(normalized[index]);
            if (!std::isalnum(character) && character != '-' && character != '_')
            {
                return false;
            }
        }
        start = end + 1;
    }
    return true;
}

} // namespace

ChannelPolicy ChannelPolicy::Build(const tailgate::types::netmap::NetworkConfig& config,
                                   bool routeAllTraffic)
{
    ChannelPolicy result;
    result.Ipv4Address = config.SelfAddress();
    for (const auto& address : config.SelfAddresses())
    {
        if (address.find(':') != std::string::npos)
        {
            result.Ipv6Addresses.push_back(address);
        }
    }
    std::sort(result.Ipv6Addresses.begin(), result.Ipv6Addresses.end());
    result.Ipv6Addresses.erase(
        std::unique(result.Ipv6Addresses.begin(), result.Ipv6Addresses.end()),
        result.Ipv6Addresses.end());
    result.Routes = tailgate::wgengine::router::Config::Build(
                        config,
                        tailgate::wgengine::router::ConfigOptions{
                            .AdditionalRoutes = {tailgate::net::packet::Ipv4Prefix(
                                VpnConstants::Network::ServiceIpv4Address, 32)},
                            .RouteAllTraffic = routeAllTraffic,
                        })
                        .Routes();
    const auto append = [&](const std::string& name, const std::vector<std::string>& resolvers)
    {
        const auto suffix = NormalizeDnsName(name);
        if (!IsDnsNamespace(suffix) || std::any_of(result.DnsNamespaces.begin(),
                                                   result.DnsNamespaces.end(),
                                                   [&](const auto& entry)
                                                   {
                                                       return entry.Suffix == suffix;
                                                   }))
        {
            return;
        }
        result.DnsNamespaces.push_back(DnsNamespace{
            .Suffix = suffix,
            .Resolvers =
                resolvers.empty()
                    ? std::vector<std::string>{tailgate::net::Ipv4Address::FromHostOrder(
                                                   VpnConstants::Network::ServiceIpv4Address)
                                                   .ToString()}
                    : resolvers,
        });
    };
    for (const auto& route : config.DnsRoutes())
    {
        append(route.Suffix, route.Resolvers);
    }
    for (const auto& domain : config.DnsDomains())
    {
        append(domain, {});
    }
    return result;
}

} // namespace tailgate::uwp::bg::manager
