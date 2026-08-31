#include "tailgate/wgengine/router/Config.h"

#include <algorithm>
#include <optional>

#include <tailgate/net/Ipv4Address.h>

namespace tailgate::wgengine::router
{
namespace
{

constexpr tailgate::net::packet::Ipv4Prefix
    TailnetRoute(tailgate::net::Ipv4Address::FromOctets(100, 64, 0, 0).HostOrder(), 10);
constexpr tailgate::net::packet::Ipv4Prefix
    LowerDefaultRoute(tailgate::net::Ipv4Address::FromOctets(0, 0, 0, 0).HostOrder(), 1);
constexpr tailgate::net::packet::Ipv4Prefix
    UpperDefaultRoute(tailgate::net::Ipv4Address::FromOctets(128, 0, 0, 0).HostOrder(), 1);

void AppendAddress(std::vector<std::string>& addresses, const std::string& address)
{
    if (!address.empty() &&
        std::find(addresses.begin(), addresses.end(), address) == addresses.end())
    {
        addresses.push_back(address);
    }
}

void AppendRoute(std::vector<tailgate::net::packet::Ipv4Prefix>& routes,
                 const tailgate::net::packet::Ipv4Prefix& route)
{
    if (route.PrefixLength() <= 32 &&
        std::find(routes.begin(), routes.end(), route) == routes.end())
    {
        routes.push_back(route);
    }
}

} // namespace

Config Config::Build(const tailgate::types::netmap::NetworkConfig& networkMap,
                     const ConfigOptions& options)
{
    Config result;
    AppendAddress(result.m_localAddresses, networkMap.SelfAddress());
    for (const std::string& address : networkMap.SelfAddresses())
    {
        AppendAddress(result.m_localAddresses, address);
    }

    AppendRoute(result.m_routes, TailnetRoute);
    if (options.RouteAllTraffic)
    {
        AppendRoute(result.m_routes, LowerDefaultRoute);
        AppendRoute(result.m_routes, UpperDefaultRoute);
    }
    if (const std::optional<tailgate::net::Ipv4Address> dnsResolver =
            tailgate::net::Ipv4Address::TryParse(networkMap.DnsResolver()))
    {
        AppendRoute(result.m_routes,
                    tailgate::net::packet::Ipv4Prefix(dnsResolver->HostOrder(), 32));
    }
    for (const tailgate::types::netmap::PeerConfig& peer : networkMap.Peers())
    {
        for (const tailgate::net::packet::Ipv4Prefix& route : peer.AllowedPrefixes())
        {
            if (route.PrefixLength() == 0 || (route.PrefixLength() >= TailnetRoute.PrefixLength() &&
                                              TailnetRoute.Contains(route.Network())))
            {
                continue;
            }
            AppendRoute(result.m_routes, route);
        }
    }
    for (const tailgate::net::packet::Ipv4Prefix& route : options.AdditionalRoutes)
    {
        AppendRoute(result.m_routes, route);
    }
    std::sort(result.m_routes.begin(),
              result.m_routes.end(),
              [](const auto& left, const auto& right)
              {
                  return left.Network() < right.Network() ||
                         (left.Network() == right.Network() &&
                          left.PrefixLength() < right.PrefixLength());
              });
    return result;
}

const std::vector<std::string>& Config::LocalAddresses() const noexcept
{
    return m_localAddresses;
}

const std::vector<tailgate::net::packet::Ipv4Prefix>& Config::Routes() const noexcept
{
    return m_routes;
}

} // namespace tailgate::wgengine::router
