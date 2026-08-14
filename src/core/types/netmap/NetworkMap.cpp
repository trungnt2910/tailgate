#include <tailgate/types/netmap/NetworkMap.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <format>
#include <stdexcept>
#include <string_view>

#include <nlohmann/json.hpp>

namespace tailgate::types::netmap
{
namespace
{

std::uint64_t NodeId(const nlohmann::json& node)
{
    return node.value("ID", 0ULL);
}

// PeerSeenChange carries no timestamp, only "was just seen"; like the upstream client, the
// receiver stamps its own current time.
std::string CurrentRfc3339Time()
{
    return std::format("{:%Y-%m-%dT%H:%M:%SZ}",
                       std::chrono::floor<std::chrono::seconds>(std::chrono::system_clock::now()));
}

std::string TimeText(const nlohmann::json& value)
{
    return value.is_string() ? value.get<std::string>() : std::string();
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
    const std::optional<std::uint32_t> address = tailgate::net::packet::ParseIpv4(host);
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

std::pair<std::string, int> StunEndpoint(const nlohmann::json& region)
{
    for (const nlohmann::json& node : region.at("Nodes"))
    {
        const int port = node.value("STUNPort", 3478);
        if (port < 0)
        {
            continue;
        }
        const std::string ipv4 = node.value("IPv4", "");
        if (!ipv4.empty() && ipv4 != "none")
        {
            return {ipv4, port};
        }
        const std::string hostname = node.value("HostName", "");
        if (!hostname.empty())
        {
            return {hostname, port};
        }
    }
    return {"", 3478};
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
    return StringArray(dns, "Domains");
}

std::optional<nlohmann::json> FindUserProfile(const nlohmann::json& map, std::uint64_t userId)
{
    if (!map.contains("UserProfiles") || !map.at("UserProfiles").is_array())
    {
        return std::nullopt;
    }
    for (const nlohmann::json& profile : map.at("UserProfiles"))
    {
        if (profile.value("ID", 0ULL) == userId)
        {
            return profile;
        }
    }
    if (map.at("UserProfiles").empty())
    {
        return std::nullopt;
    }
    return map.at("UserProfiles").front();
}

std::string TailnetDisplayName(const nlohmann::json& map)
{
    const auto node = map.find("Node");
    if (node == map.end() || !node->is_object())
    {
        return {};
    }
    const auto capMap = node->find("CapMap");
    if (capMap == node->end() || !capMap->is_object())
    {
        return {};
    }
    const auto displayNames = capMap->find("tailnet-display-name");
    if (displayNames == capMap->end() || !displayNames->is_array() || displayNames->empty())
    {
        return {};
    }
    const nlohmann::json& displayName = displayNames->front();
    return displayName.is_string() ? displayName.get<std::string>() : "";
}

std::vector<std::string> Capabilities(const nlohmann::json& map)
{
    const auto node = map.find("Node");
    if (node == map.end() || !node->is_object())
    {
        return {};
    }
    const auto capMap = node->find("CapMap");
    if (capMap == node->end() || !capMap->is_object())
    {
        return {};
    }
    std::vector<std::string> result;
    for (const auto& [name, value] : capMap->items())
    {
        (void)value;
        result.push_back(name);
    }
    return result;
}

std::string TrimTrailingDot(std::string value)
{
    if (!value.empty() && value.back() == '.')
    {
        value.pop_back();
    }
    return value;
}

std::string MagicDnsDomainFromNodeName(const std::string& nodeName)
{
    const std::string name = TrimTrailingDot(nodeName);
    const std::size_t dot = name.find('.');
    if (dot == std::string::npos || dot + 1 >= name.size())
    {
        return {};
    }
    return name.substr(dot + 1);
}

void ApplyAccountMetadata(NetworkConfig& config, const nlohmann::json& map)
{
    const std::string tailnetDisplayName = TailnetDisplayName(map);
    if (!tailnetDisplayName.empty())
    {
        config.TailnetDisplayName = tailnetDisplayName;
    }
    const auto node = map.find("Node");
    const std::uint64_t userId =
        node != map.end() && node->is_object() ? node->value("User", 0ULL) : 0ULL;
    const std::optional<nlohmann::json> profile = FindUserProfile(map, userId);
    if (!profile)
    {
        return;
    }
    config.AccountName = profile->value("LoginName", "");
    config.AccountDisplayName = profile->value("DisplayName", "");
    config.AccountProfilePicUrl = profile->value("ProfilePicURL", "");
    // Tag-authenticated nodes belong to the synthetic "tagged-devices" user; surface the human
    // account when the map includes one.
    if (config.AccountName.find('@') == std::string::npos)
    {
        for (const nlohmann::json& candidate : map.at("UserProfiles"))
        {
            const std::string login = candidate.value("LoginName", "");
            if (login.find('@') != std::string::npos)
            {
                config.AccountName = login;
                config.AccountDisplayName = candidate.value("DisplayName", "");
                config.AccountProfilePicUrl = candidate.value("ProfilePicURL", "");
                break;
            }
        }
    }
}

bool MergeUserProfiles(NetworkConfig& config, const nlohmann::json& map)
{
    if (!map.contains("UserProfiles") || !map.at("UserProfiles").is_array())
    {
        return false;
    }
    for (const nlohmann::json& source : map.at("UserProfiles"))
    {
        const std::uint64_t id = source.value("ID", 0ULL);
        if (id == 0)
        {
            continue;
        }
        UserProfile profile{.Id = id,
                            .LoginName = source.value("LoginName", ""),
                            .DisplayName = source.value("DisplayName", ""),
                            .ProfilePicUrl = source.value("ProfilePicURL", "")};
        const auto existing = std::find_if(config.UserProfiles.begin(),
                                           config.UserProfiles.end(),
                                           [id](const UserProfile& candidate)
                                           {
                                               return candidate.Id == id;
                                           });
        if (existing == config.UserProfiles.end())
        {
            config.UserProfiles.push_back(std::move(profile));
        }
        else
        {
            *existing = std::move(profile);
        }
    }
    return true;
}

std::string OwnerName(const std::vector<UserProfile>& profiles, std::uint64_t ownerId)
{
    const auto profile = std::find_if(profiles.begin(),
                                      profiles.end(),
                                      [ownerId](const UserProfile& candidate)
                                      {
                                          return candidate.Id == ownerId;
                                      });
    if (profile == profiles.end())
    {
        return {};
    }
    return profile->DisplayName.empty() ? profile->LoginName : profile->DisplayName;
}

void RefreshPeerOwners(NetworkConfig& config)
{
    for (PeerConfig& peer : config.Peers)
    {
        const std::string owner = OwnerName(config.UserProfiles, peer.OwnerId);
        if (!owner.empty())
        {
            peer.Owner = owner;
        }
    }
}

void ApplyDerpMetadata(PeerConfig& peer, const nlohmann::json& regions)
{
    if (peer.DerpRegion == 0)
    {
        return;
    }
    const auto region = regions.find(std::format("{}", peer.DerpRegion));
    if (region != regions.end())
    {
        peer.DerpCode = region->value("RegionCode", std::format("derp-{}", peer.DerpRegion));
        peer.DerpHost = DerpHost(*region);
    }
}

void ApplyHostInfoMetadata(NetworkConfig& config, const nlohmann::json& node)
{
    if (!node.contains("Hostinfo") || !node.at("Hostinfo").is_object())
    {
        return;
    }
    const nlohmann::json& hostInfo = node.at("Hostinfo");
    config.SelfClientVersion = hostInfo.value("IPNVersion", "");
    config.SelfWireIngress = hostInfo.value("WireIngress", false);
    config.SelfIngressEnabled = hostInfo.value("IngressEnabled", false);
    config.SelfPeerApi4Port = 0;
    config.SelfPeerApi6Port = 0;
    if (!hostInfo.contains("Services") || !hostInfo.at("Services").is_array())
    {
        return;
    }
    for (const nlohmann::json& service : hostInfo.at("Services"))
    {
        const std::string protocol = service.value("Proto", "");
        if (protocol == "peerapi4")
        {
            config.SelfPeerApi4Port = service.value("Port", 0);
        }
        else if (protocol == "peerapi6")
        {
            config.SelfPeerApi6Port = service.value("Port", 0);
        }
    }
}

PeerConfig Peer(const nlohmann::json& node,
                const nlohmann::json& regions,
                const std::vector<UserProfile>& profiles)
{
    const auto addresses = StringArray(node, "Addresses");
    PeerConfig peer;
    peer.NodeId = NodeId(node);
    peer.Name = node.value("Name", "");
    peer.OwnerId = node.value("User", 0ULL);
    peer.Owner = OwnerName(profiles, peer.OwnerId);
    for (const std::string& address : addresses)
    {
        peer.Addresses.push_back(address.substr(0, address.find('/')));
    }
    if (!peer.Addresses.empty())
    {
        const auto ipv4 = std::find_if(peer.Addresses.begin(),
                                       peer.Addresses.end(),
                                       [](const std::string& address)
                                       {
                                           return address.find(':') == std::string::npos;
                                       });
        peer.Address = ipv4 == peer.Addresses.end() ? peer.Addresses.front() : *ipv4;
    }
    peer.Key = node.value("Key", "");
    peer.DiscoKey = node.value("DiscoKey", "");
    peer.Online = node.value("Online", false);
    peer.LastSeen = node.value("LastSeen", "");
    peer.KeyExpiry = node.value("KeyExpiry", "");
    if (node.contains("Hostinfo") && node.at("Hostinfo").is_object())
    {
        const nlohmann::json& hostInfo = node.at("Hostinfo");
        peer.OperatingSystem = hostInfo.value("OS", "");
        peer.ClientVersion = hostInfo.value("IPNVersion", "");
        peer.WireIngress = hostInfo.value("WireIngress", false);
        peer.IngressEnabled = hostInfo.value("IngressEnabled", false);
        if (hostInfo.contains("Services") && hostInfo.at("Services").is_array())
        {
            for (const nlohmann::json& service : hostInfo.at("Services"))
            {
                const std::string protocol = service.value("Proto", "");
                if (protocol == "peerapi4")
                {
                    peer.PeerApi4Port = service.value("Port", 0);
                }
                else if (protocol == "peerapi6")
                {
                    peer.PeerApi6Port = service.value("Port", 0);
                }
            }
        }
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
        const auto prefix = tailgate::net::packet::ParseIpv4Prefix(text);
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

std::vector<PeerConfig> Peers(const nlohmann::json& map, const std::vector<UserProfile>& profiles)
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
        result.push_back(Peer(node, regions, profiles));
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
    config.CertDomains = StringArray(dns, "CertDomains");
    config.DnsDefaultResolvers = ResolverArray(dns.value("Resolvers", nlohmann::json::array()));
    if (config.DnsDefaultResolvers.empty())
    {
        config.DnsDefaultResolvers =
            ResolverArray(dns.value("FallbackResolvers", nlohmann::json::array()));
    }
    config.DnsRoutes.clear();
    for (const auto& [suffix, resolvers] : dns.at("Routes").items())
    {
        config.DnsRoutes.push_back(
            NetworkConfig::DnsRoute{.Suffix = suffix, .Resolvers = ResolverArray(resolvers)});
    }
}

} // namespace

NetworkConfig ParseNetworkMap(const std::string& text)
{
    const nlohmann::json map = nlohmann::json::parse(text);
    NetworkConfig result;
    result.Domain = map.value("Domain", "");
    (void)MergeUserProfiles(result, map);
    ApplyAccountMetadata(result, map);
    const nlohmann::json& node = map.at("Node");
    result.SelfNodeId = NodeId(node);
    result.SelfKey = node.value("Key", "");
    result.SelfName = TrimTrailingDot(node.value("Name", ""));
    result.SelfMachineAuthorized = node.value("MachineAuthorized", false);
    result.MagicDnsDomain = MagicDnsDomainFromNodeName(result.SelfName);
    result.Capabilities = Capabilities(map);
    ApplyHostInfoMetadata(result, node);
    for (const std::string& address : StringArray(node, "Addresses"))
    {
        result.SelfAddresses.push_back(address.substr(0, address.find('/')));
    }
    const auto selfIpv4 =
        std::find_if(result.SelfAddresses.begin(),
                     result.SelfAddresses.end(),
                     [](const std::string& address)
                     {
                         return tailgate::net::packet::ParseIpv4(address).has_value();
                     });
    if (selfIpv4 != result.SelfAddresses.end())
    {
        result.SelfAddress = *selfIpv4;
    }
    else if (!result.SelfAddresses.empty())
    {
        result.SelfAddress = result.SelfAddresses.front();
    }
    const nlohmann::json& dns = map.at("DNSConfig");
    ApplyDnsConfig(result, dns);
    result.Peers = Peers(map, result.UserProfiles);

    for (const std::string& resolverText : DnsResolvers(dns))
    {
        const auto resolver = tailgate::net::packet::ParseIpv4(resolverText);
        if (!resolver)
        {
            continue;
        }
        for (const PeerConfig& peer : result.Peers)
        {
            if (std::any_of(peer.AllowedPrefixes.begin(),
                            peer.AllowedPrefixes.end(),
                            [&](const tailgate::net::packet::Ipv4Prefix& prefix)
                            {
                                return tailgate::net::packet::Contains(prefix, *resolver);
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
        throw std::runtime_error("Network map did not provide a reachable IPv4 DNS resolver.");
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
            throw std::runtime_error("Network map did not provide a DERP region.");
        }
        result.DerpRegion = peer->DerpRegion;
    }
    const nlohmann::json& region =
        map.at("DERPMap").at("Regions").at(std::format("{}", result.DerpRegion));
    result.DerpCode = region.value("RegionCode", std::format("derp-{}", result.DerpRegion));
    result.DerpHost = DerpHost(region);
    const auto [stunHost, stunPort] = StunEndpoint(region);
    result.StunHost = stunHost;
    result.StunPort = stunPort;
    if (result.DerpHost.empty())
    {
        throw std::runtime_error("Selected DERP region has no usable hostname.");
    }
    return result;
}

bool ApplyNetworkMapUpdate(NetworkConfig& config, const std::string& text)
{
    const nlohmann::json map = nlohmann::json::parse(text);
    config.RemovedPeerNodeIds.clear();
    if (map.value("KeepAlive", false))
    {
        return false;
    }

    bool changed = false;
    if (map.contains("Domain"))
    {
        config.Domain = map.value("Domain", "");
        changed = true;
    }
    const bool userProfilesChanged = MergeUserProfiles(config, map);
    if (map.contains("Node") || userProfilesChanged)
    {
        if (map.contains("Node") && map.at("Node").is_object() && map.at("Node").contains("Name"))
        {
            config.SelfName = TrimTrailingDot(map.at("Node").value("Name", ""));
            config.SelfKey = map.at("Node").value("Key", config.SelfKey);
            config.MagicDnsDomain = MagicDnsDomainFromNodeName(config.SelfName);
        }
        if (map.contains("Node") && map.at("Node").is_object() &&
            map.at("Node").contains("MachineAuthorized"))
        {
            config.SelfMachineAuthorized = map.at("Node").value("MachineAuthorized", false);
        }
        if (map.contains("Node") && map.at("Node").is_object() && map.at("Node").contains("CapMap"))
        {
            config.Capabilities = Capabilities(map);
        }
        ApplyAccountMetadata(config, map);
        changed = true;
    }
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
        const auto homeRegion = updateRegions.find(std::format("{}", config.DerpRegion));
        if (homeRegion != updateRegions.end())
        {
            config.DerpCode =
                homeRegion->value("RegionCode", std::format("derp-{}", config.DerpRegion));
            config.DerpHost = DerpHost(*homeRegion);
            const auto [stunHost, stunPort] = StunEndpoint(*homeRegion);
            config.StunHost = stunHost;
            config.StunPort = stunPort;
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
            config.RemovedPeerNodeIds.push_back(nodeId);
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
            PeerConfig peer = Peer(node, updateRegions, config.UserProfiles);
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
                if (peer.Owner.empty())
                {
                    // Incremental updates usually omit UserProfiles; keep the known owner.
                    peer.Owner = existing->Owner;
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
        // Like the upstream client, this only refreshes LastSeen. Online state is carried
        // exclusively by OnlineChange and PeersChangedPatch; mistaking "seen" for "online"
        // previously made peers flicker between states in the UI.
        for (const auto& [id, seen] : map.at("PeerSeenChange").items())
        {
            auto peer = FindPeer(config, std::stoull(id));
            if (peer != config.Peers.end())
            {
                peer->LastSeen = seen.get<bool>() ? CurrentRfc3339Time() : std::string();
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
            if (patch.contains("LastSeen"))
            {
                peer->LastSeen = TimeText(patch.at("LastSeen"));
            }
            if (patch.contains("KeyExpiry"))
            {
                peer->KeyExpiry = TimeText(patch.at("KeyExpiry"));
            }
            // Cap and CapMap changes are intentionally not modeled: Tailgate consumes no
            // per-peer capability metadata.
            changed = true;
        }
    }
    if (userProfilesChanged)
    {
        RefreshPeerOwners(config);
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
        for (const tailgate::net::packet::Ipv4Prefix& prefix : peers[index].AllowedPrefixes)
        {
            if (prefix.PrefixLength == 0 && exitNode != index)
            {
                continue;
            }
            if (tailgate::net::packet::Contains(prefix, destination) &&
                prefix.PrefixLength > bestPrefixLength)
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
    return peer == config.Peers.end() ? std::format("derp-{}", region) : peer->DerpCode;
}

bool HasCapability(const NetworkConfig& config, const std::string& capability)
{
    return std::find(config.Capabilities.begin(), config.Capabilities.end(), capability) !=
           config.Capabilities.end();
}

bool AllowsPortToken(const std::string& token, int port)
{
    const std::size_t dash = token.find('-');
    int start = 0;
    int end = 0;
    const auto parse = [](std::string_view value, int& out)
    {
        const char* begin = value.data();
        const char* finish = value.data() + value.size();
        const auto parsed = std::from_chars(begin, finish, out);
        return parsed.ec == std::errc{} && parsed.ptr == finish;
    };
    if (dash == std::string::npos)
    {
        return parse(token, start) && start == port;
    }
    return parse(std::string_view(token).substr(0, dash), start) &&
           parse(std::string_view(token).substr(dash + 1), end) && start <= port && port <= end;
}

bool AllowsFunnelPort(const NetworkConfig& config, int port)
{
    constexpr std::string_view prefix = "https://tailscale.com/cap/funnel-ports";
    for (const std::string& capability : config.Capabilities)
    {
        if (capability.rfind(std::string(prefix), 0) != 0)
        {
            continue;
        }
        const std::size_t query = capability.find("ports=");
        if (query == std::string::npos)
        {
            continue;
        }
        std::size_t start = query + 6;
        while (start <= capability.size())
        {
            const std::size_t comma = capability.find(',', start);
            const std::string token = capability.substr(
                start, comma == std::string::npos ? std::string::npos : comma - start);
            if (AllowsPortToken(token, port))
            {
                return true;
            }
            if (comma == std::string::npos)
            {
                break;
            }
            start = comma + 1;
        }
    }
    return false;
}

} // namespace tailgate::types::netmap
