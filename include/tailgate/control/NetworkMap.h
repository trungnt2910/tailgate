#pragma once

#include "tailgate/network/Ipv4.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tailgate::control
{

struct PeerConfig
{
    std::uint64_t NodeId = 0;
    std::string Name;
    std::string Address;
    std::string Key;
    std::string DiscoKey;
    std::vector<std::string> Endpoints;
    std::vector<network::Ipv4Prefix> AllowedPrefixes;
    int DerpRegion = 0;
    std::string DerpCode;
    std::string DerpHost;
    std::string OperatingSystem;
    bool Online = false;
    bool ExitNodeOption = false;
};

struct NetworkConfig
{
    struct DnsRoute
    {
        std::string Suffix;
        std::vector<std::string> Resolvers;
    };

    std::string SelfAddress;
    std::string DnsResolver;
    std::vector<std::string> DnsDomains;
    std::vector<std::string> DnsDefaultResolvers;
    std::vector<DnsRoute> DnsRoutes;
    int DerpRegion = 0;
    std::string DerpHost;
    std::string DerpCode;
    std::vector<PeerConfig> Peers;
};

[[nodiscard]] NetworkConfig ParseNetworkMap(const std::string& json);
[[nodiscard]] bool ApplyNetworkMapUpdate(NetworkConfig& config, const std::string& json);
[[nodiscard]] std::optional<std::size_t>
FindRoute(const std::vector<PeerConfig>& peers,
          std::uint32_t destination,
          std::optional<std::size_t> exitNode = std::nullopt);
[[nodiscard]] std::optional<std::size_t> FindExitNode(const std::vector<PeerConfig>& peers,
                                                      const std::string& nameOrAddress,
                                                      bool requireOnline = false);
[[nodiscard]] std::string DerpCode(const NetworkConfig& config, int region);

} // namespace tailgate::control
