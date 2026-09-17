#pragma once

#include <map>
#include <string>
#include <vector>

#include <tailgate/net/IpRange.h>

namespace tailgate::types::netmap
{

// Presence-only application grants. Values are not authorization data for a local
// exporter: Tailgate does not expose files; each remote PeerAPI enforces its own ACLs.
struct CapabilityPresenceGrant
{
    std::vector<net::IpRange> Sources;
    std::vector<net::IpRange> Destinations;
    std::vector<std::string> Names;
};

using NamedCapabilityFilters = std::map<std::string, std::vector<CapabilityPresenceGrant>>;

class NetworkConfig;
void RefreshPeerCapabilities(NetworkConfig& configuration);

} // namespace tailgate::types::netmap
