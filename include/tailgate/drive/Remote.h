#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <tailgate/net/IpAddress.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::drive
{

struct Remote
{
    std::uint64_t NodeId = 0;
    std::string NodeKey;
    std::string Name;
    std::optional<net::IpAddress> Ipv4;
    std::optional<net::IpAddress> Ipv6;
    std::uint16_t PeerApi4Port = 0;
    std::uint16_t PeerApi6Port = 0;

    bool operator==(const Remote&) const = default;
};

// Recompute for every netmap update. Only currently available, authorized remotes are returned;
// these netmap-derived addresses are the only permitted outbound Taildrive destinations.
[[nodiscard]] std::vector<Remote> DiscoverRemotes(const types::netmap::NetworkConfig& config);

} // namespace tailgate::drive
