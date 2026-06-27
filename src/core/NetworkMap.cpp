#include "tailgate/control/NetworkMap.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <stdexcept>

namespace tailgate::control
{
namespace
{

std::uint64_t NodeId(const nlohmann::json& node)
{
    return node.value("ID", 0ULL);
}

std::vector<std::string> StringArray(const nlohmann::json& object, const char* name)
{
    if (!object.contains(name) || !object.at(name).is_array())
    {
        return {};
    }
    return object.at(name).get<std::vector<std::string>>();
}

std::optional<std::string> KeyText(const nlohmann::json& value, const char* prefix)
{
    if (value.is_string())
    {
        return value.get<std::string>();
    }
    if (!value.is_object())
    {
        return std::nullopt;
    }
    for (const char* field : {"String", "Public", "Key", "Value"})
    {
        const auto found = value.find(field);
        if (found != value.end() && found->is_string())
        {
            return found->get<std::string>();
        }
    }
    const auto raw = value.find("Raw32");
    if (raw != value.end() && raw->is_string())
    {
        return std::string(prefix) + raw->get<std::string>();
    }
    return std::nullopt;
}

int EndpointPreference(const std::string& endpoint)
{
    const std::size_t colon = endpoint.rfind(':');
    if (colon == std::string::npos || endpoint.find('[') != std::string::npos)
    {
        return 100;
    }
    const std::string host = endpoint.substr(0, colon);
    const std::optional<std::uint32_t> address = network::ParseIpv4(host);
    if (!address)
    {
        return 100;
    }
    if ((*address & 0xff000000U) == 0x0a000000U || (*address & 0xfff00000U) == 0xac100000U ||
        (*address & 0xffff0000U) == 0xc0a80000U)
    {
        return 1;
    }
    return 0;
}

std::string DerpHost(const nlohmann::json& region)
{
    for (const nlohmann::json& node : region.at("Nodes"))
    {
        if (!node.value("STUNOnly", false) && node.contains("HostName"))
        {
            return node.at("HostName").get<std::string>();
        }
    }
    return {};
}

std::vector<std::string> DnsResolvers(const nlohmann::json& dns)
{
    std::vector<std::string> result;
    for (const auto& [domain, route] : dns.at("Routes").items())
    {
        (void)domain;
        if (route.is_array())
        {
            for (const nlohmann::json& resolver : route)
            {
                if (resolver.contains("Addr"))
                {
                    result.push_back(resolver.at("Addr").get<std::string>());
                }
            }
        }
    }
    return result;
}

std::vector<std::string> ResolverArray(const nlohmann::json& resolvers)
{
    std::vector<std::string> result;
    if (!resolvers.is_array())
    {
        return result;
    }
    for (const nlohmann::json& resolver : resolvers)
    {
        const std::string address = resolver.value("Addr", "");
        if (!address.empty())
        {
            result.push_back(address);
        }
    }
    return result;
}

std::vector<std::string> DnsDomains(const nlohmann::json& dns)
{
    std::vector<std::string> result = StringArray(dns, "Domains");
    for (const auto& [routeName, route] : dns.at("Routes").items())
    {
        (void)route;
        std::string domain = routeName;
        if (!domain.empty() && domain.back() == '.')
        {
            domain.pop_back();
        }
        if (!domain.empty() && std::find(result.begin(), result.end(), domain) == result.end())
        {
            result.push_back(std::move(domain));
        }
    }
    return result;
}

void ApplyDerpMetadata(PeerConfig& peer, const nlohmann::json& regions)
{
    if (peer.DerpRegion == 0)
    {
        return;
    }
    const auto region = regions.find(std::to_string(peer.DerpRegion));
    if (region != regions.end())
    {
        peer.DerpCode = region->value("RegionCode", "derp-" + std::to_string(peer.DerpRegion));
        peer.DerpHost = DerpHost(*region);
    }
}

PeerConfig Peer(const nlohmann::json& node, const nlohmann::json& regions)
{
    const auto addresses = StringArray(node, "Addresses");
    PeerConfig peer;
    peer.NodeId = NodeId(node);
    peer.Name = node.value("Name", "");
    if (!addresses.empty())
    {
        peer.Address = addresses.front().substr(0, addresses.front().find('/'));
    }
    peer.Key = node.value("Key", "");
    peer.DiscoKey = node.value("DiscoKey", "");
    peer.Online = node.value("Online", false);
    if (node.contains("Hostinfo") && node.at("Hostinfo").is_object())
    {
        peer.OperatingSystem = node.at("Hostinfo").value("OS", "");
    }
    const std::string derp = node.value("DERP", "");
    const std::size_t colon = derp.rfind(':');
    if (colon != std::string::npos)
    {
        peer.DerpRegion = std::stoi(derp.substr(colon + 1));
        ApplyDerpMetadata(peer, regions);
    }
    for (const std::string& endpoint : StringArray(node, "Endpoints"))
    {
        if (EndpointPreference(endpoint) < 100)
        {
            peer.Endpoints.push_back(endpoint);
        }
    }
    std::stable_sort(peer.Endpoints.begin(),
                     peer.Endpoints.end(),
                     [](const std::string& left, const std::string& right)
                     {
                         return EndpointPreference(left) < EndpointPreference(right);
                     });
    std::vector<std::string> allowed = StringArray(node, "AllowedIPs");
    allowed.insert(allowed.end(), addresses.begin(), addresses.end());
    for (const std::string& text : allowed)
    {
        const auto prefix = network::ParseIpv4Prefix(text);
        if (prefix && prefix->PrefixLength == 0)
        {
            peer.ExitNodeOption = true;
        }
        else if (prefix)
        {
            peer.AllowedPrefixes.push_back(*prefix);
        }
    }
    return peer;
}

std::vector<PeerConfig> Peers(const nlohmann::json& map)
{
    const nlohmann::json& regions = map.at("DERPMap").at("Regions");
    std::vector<PeerConfig> result;
    for (const nlohmann::json& node : map.at("Peers"))
    {
        const auto addresses = StringArray(node, "Addresses");
        if (addresses.empty())
        {
            continue;
        }
        result.push_back(Peer(node, regions));
    }
    return result;
}

std::vector<PeerConfig>::iterator FindPeer(NetworkConfig& config, std::uint64_t nodeId)
{
    return std::find_if(config.Peers.begin(),
                        config.Peers.end(),
                        [nodeId](const PeerConfig& peer)
                        {
                            return peer.NodeId == nodeId;
                        });
}

void ApplyDnsConfig(NetworkConfig& config, const nlohmann::json& dns)
{
    config.DnsDomains = DnsDomains(dns);
    config.DnsDefaultResolvers = ResolverArray(dns.value("Resolvers", nlohmann::json::array()));
    if (config.DnsDefaultResolvers.empty())
    {
        config.DnsDefaultResolvers =
            ResolverArray(dns.value("FallbackResolvers", nlohmann::json::array()));
    }
    config.DnsRoutes.clear();
    for (const auto& [suffix, resolvers] : dns.at("Routes").items())
    {
        config.DnsRoutes.push_back({suffix, ResolverArray(resolvers)});
    }
}

} // namespace

NetworkConfig ParseNetworkMap(const std::string& text)
{
    const nlohmann::json map = nlohmann::json::parse(text);
    NetworkConfig result;
    const std::string self = map.at("Node").at("Addresses").at(0).get<std::string>();
    result.SelfAddress = self.substr(0, self.find('/'));
    const nlohmann::json& dns = map.at("DNSConfig");
    ApplyDnsConfig(result, dns);
    result.Peers = Peers(map);

    for (const std::string& resolverText : DnsResolvers(dns))
    {
        const auto resolver = network::ParseIpv4(resolverText);
        if (!resolver)
        {
            continue;
        }
        for (const PeerConfig& peer : result.Peers)
        {
            if (std::any_of(peer.AllowedPrefixes.begin(),
                            peer.AllowedPrefixes.end(),
                            [&](const network::Ipv4Prefix& prefix)
                            {
                                return network::Contains(prefix, *resolver);
                            }))
            {
                result.DnsResolver = resolverText;
                result.DerpRegion = peer.DerpRegion;
                break;
            }
        }
        if (!result.DnsResolver.empty())
        {
            break;
        }
    }
    if (result.DnsResolver.empty())
    {
        throw std::runtime_error("netmap did not provide a reachable IPv4 DNS resolver");
    }
    if (result.DerpRegion == 0)
    {
        const auto peer = std::find_if(result.Peers.begin(),
                                       result.Peers.end(),
                                       [](const PeerConfig& value)
                                       {
                                           return value.DerpRegion != 0;
                                       });
        if (peer == result.Peers.end())
        {
            throw std::runtime_error("netmap did not provide a DERP region");
        }
        result.DerpRegion = peer->DerpRegion;
    }
    const nlohmann::json& region =
        map.at("DERPMap").at("Regions").at(std::to_string(result.DerpRegion));
    result.DerpCode = region.value("RegionCode", "derp-" + std::to_string(result.DerpRegion));
    result.DerpHost = DerpHost(region);
    if (result.DerpHost.empty())
    {
        throw std::runtime_error("selected DERP region has no usable hostname");
    }
    return result;
}

bool ApplyNetworkMapUpdate(NetworkConfig& config, const std::string& text)
{
    const nlohmann::json map = nlohmann::json::parse(text);
    if (map.value("KeepAlive", false))
    {
        return false;
    }

    bool changed = false;
    const nlohmann::json updateRegions =
        map.contains("DERPMap") && map.at("DERPMap").contains("Regions")
            ? map.at("DERPMap").at("Regions")
            : nlohmann::json::object();
    if (map.contains("DNSConfig") && map.at("DNSConfig").is_object())
    {
        ApplyDnsConfig(config, map.at("DNSConfig"));
        changed = true;
    }
    if (!updateRegions.empty())
    {
        const auto homeRegion = updateRegions.find(std::to_string(config.DerpRegion));
        if (homeRegion != updateRegions.end())
        {
            config.DerpCode =
                homeRegion->value("RegionCode", "derp-" + std::to_string(config.DerpRegion));
            config.DerpHost = DerpHost(*homeRegion);
        }
        for (PeerConfig& peer : config.Peers)
        {
            ApplyDerpMetadata(peer, updateRegions);
        }
        changed = true;
    }
    if (map.contains("PeersRemoved"))
    {
        for (const nlohmann::json& id : map.at("PeersRemoved"))
        {
            const std::uint64_t nodeId = id.get<std::uint64_t>();
            config.Peers.erase(std::remove_if(config.Peers.begin(),
                                              config.Peers.end(),
                                              [nodeId](const PeerConfig& peer)
                                              {
                                                  return peer.NodeId == nodeId;
                                              }),
                               config.Peers.end());
        }
        changed = true;
    }
    if (map.contains("PeersChanged"))
    {
        for (const nlohmann::json& node : map.at("PeersChanged"))
        {
            PeerConfig peer = Peer(node, updateRegions);
            auto existing = FindPeer(config, peer.NodeId);
            if (existing == config.Peers.end())
            {
                config.Peers.push_back(std::move(peer));
            }
            else
            {
                if (peer.DerpRegion == existing->DerpRegion && peer.DerpCode.empty())
                {
                    peer.DerpCode = existing->DerpCode;
                    peer.DerpHost = existing->DerpHost;
                }
                *existing = std::move(peer);
            }
        }
        changed = true;
    }
    if (map.contains("OnlineChange"))
    {
        for (const auto& [id, online] : map.at("OnlineChange").items())
        {
            auto peer = FindPeer(config, std::stoull(id));
            if (peer != config.Peers.end())
            {
                peer->Online = online.get<bool>();
                changed = true;
            }
        }
    }
    if (map.contains("PeerSeenChange"))
    {
        for (const auto& [id, seen] : map.at("PeerSeenChange").items())
        {
            auto peer = FindPeer(config, std::stoull(id));
            if (peer != config.Peers.end())
            {
                peer->Online = seen.get<bool>();
                changed = true;
            }
        }
    }
    if (map.contains("PeersChangedPatch"))
    {
        for (const nlohmann::json& patch : map.at("PeersChangedPatch"))
        {
            auto peer = FindPeer(config, patch.value("NodeID", 0ULL));
            if (peer == config.Peers.end())
            {
                continue;
            }
            if (patch.contains("DERPRegion"))
            {
                peer->DerpRegion = patch.at("DERPRegion").get<int>();
                peer->DerpCode.clear();
                peer->DerpHost.clear();
                ApplyDerpMetadata(*peer, updateRegions);
            }
            if (patch.contains("Endpoints"))
            {
                peer->Endpoints.clear();
                for (const std::string& endpoint :
                     patch.at("Endpoints").get<std::vector<std::string>>())
                {
                    if (EndpointPreference(endpoint) < 100)
                    {
                        peer->Endpoints.push_back(endpoint);
                    }
                }
                std::stable_sort(peer->Endpoints.begin(),
                                 peer->Endpoints.end(),
                                 [](const std::string& left, const std::string& right)
                                 {
                                     return EndpointPreference(left) < EndpointPreference(right);
                                 });
            }
            if (patch.contains("Key"))
            {
                if (std::optional<std::string> key = KeyText(patch.at("Key"), "nodekey:"))
                {
                    peer->Key = *key;
                }
            }
            if (patch.contains("DiscoKey"))
            {
                if (std::optional<std::string> key = KeyText(patch.at("DiscoKey"), "discokey:"))
                {
                    peer->DiscoKey = *key;
                }
            }
            if (patch.contains("Online") && patch.at("Online").is_boolean())
            {
                peer->Online = patch.at("Online").get<bool>();
            }
            changed = true;
        }
    }
    return changed;
}

std::optional<std::size_t> FindRoute(const std::vector<PeerConfig>& peers,
                                     std::uint32_t destination,
                                     std::optional<std::size_t> exitNode)
{
    std::optional<std::size_t> result;
    int bestPrefixLength = -1;
    for (std::size_t index = 0; index < peers.size(); ++index)
    {
        for (const network::Ipv4Prefix& prefix : peers[index].AllowedPrefixes)
        {
            if (prefix.PrefixLength == 0 && exitNode != index)
            {
                continue;
            }
            if (network::Contains(prefix, destination) && prefix.PrefixLength > bestPrefixLength)
            {
                result = index;
                bestPrefixLength = prefix.PrefixLength;
            }
        }
    }
    if (result)
    {
        return result;
    }
    if (exitNode && *exitNode < peers.size() && peers[*exitNode].ExitNodeOption)
    {
        return exitNode;
    }
    return std::nullopt;
}

std::optional<std::size_t> FindExitNode(const std::vector<PeerConfig>& peers,
                                        const std::string& nameOrAddress,
                                        bool requireOnline)
{
    for (std::size_t index = 0; index < peers.size(); ++index)
    {
        const PeerConfig& peer = peers[index];
        if (requireOnline && !peer.Online)
        {
            continue;
        }
        std::string name = peer.Name;
        if (!name.empty() && name.back() == '.')
        {
            name.pop_back();
        }
        const std::size_t dot = name.find('.');
        const std::string shortName = name.substr(0, dot);
        if (peer.ExitNodeOption &&
            (peer.Address == nameOrAddress || name == nameOrAddress || shortName == nameOrAddress))
        {
            return index;
        }
    }
    return std::nullopt;
}

std::string DerpCode(const NetworkConfig& config, int region)
{
    if (region == config.DerpRegion && !config.DerpCode.empty())
    {
        return config.DerpCode;
    }
    const auto peer = std::find_if(config.Peers.begin(),
                                   config.Peers.end(),
                                   [region](const PeerConfig& value)
                                   {
                                       return value.DerpRegion == region && !value.DerpCode.empty();
                                   });
    return peer == config.Peers.end() ? "derp-" + std::to_string(region) : peer->DerpCode;
}

} // namespace tailgate::control
