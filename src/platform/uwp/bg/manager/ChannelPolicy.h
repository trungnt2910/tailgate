#pragma once

#include <string>
#include <vector>

#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::uwp::bg::manager
{

struct DnsNamespace
{
    std::string Suffix;
    std::vector<std::string> Resolvers;
    [[nodiscard]] bool operator==(const DnsNamespace&) const = default;
};

struct ChannelPolicy
{
    std::string Ipv4Address;
    std::vector<std::string> Ipv6Addresses;
    std::vector<tailgate::net::packet::Ipv4Prefix> Routes;
    std::vector<DnsNamespace> DnsNamespaces;

    [[nodiscard]] static ChannelPolicy Build(const tailgate::types::netmap::NetworkConfig& config,
                                             bool routeAllTraffic);
    [[nodiscard]] bool operator==(const ChannelPolicy&) const = default;
};

} // namespace tailgate::uwp::bg::manager
