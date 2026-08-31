#include "tailgate/control/client/NetworkMapParser.h"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <format>
#include <stdexcept>
#include <string_view>

#include <nlohmann/json.hpp>

#include <tailgate/net/Endpoint.h>
#include <tailgate/net/Ipv4Address.h>

namespace tailgate::control::client
{

using tailgate::types::netmap::NetworkConfig;
using tailgate::types::netmap::PeerConfig;
using tailgate::types::netmap::UserProfile;

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
    const std::optional<tailgate::net::Endpoint> parsed =
        tailgate::net::Endpoint::TryParse(endpoint);
    if (!parsed)
    {
        return 100;
    }
    return parsed->Address().IsPrivate() ? 1 : 0;
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
        config.TailnetDisplayName(tailnetDisplayName);
    }
    const auto node = map.find("Node");
    const std::uint64_t userId =
        node != map.end() && node->is_object() ? node->value("User", 0ULL) : 0ULL;
    const std::optional<nlohmann::json> profile = FindUserProfile(map, userId);
    if (!profile)
    {
        return;
    }
    config.AccountName(profile->value("LoginName", ""));
    config.AccountDisplayName(profile->value("DisplayName", ""));
    config.AccountProfilePicUrl(profile->value("ProfilePicURL", ""));
    // Tag-authenticated nodes belong to the synthetic "tagged-devices" user; surface the human
    // account when the map includes one.
    if (config.AccountName().find('@') == std::string::npos)
    {
        for (const nlohmann::json& candidate : map.at("UserProfiles"))
        {
            const std::string login = candidate.value("LoginName", "");
            if (login.find('@') != std::string::npos)
            {
                config.AccountName(login);
                config.AccountDisplayName(candidate.value("DisplayName", ""));
                config.AccountProfilePicUrl(candidate.value("ProfilePicURL", ""));
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
    std::vector<UserProfile> profiles = config.UserProfiles();
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
        const auto existing = std::find_if(profiles.begin(),
                                           profiles.end(),
                                           [id](const UserProfile& candidate)
                                           {
                                               return candidate.Id == id;
                                           });
        if (existing == profiles.end())
        {
            profiles.push_back(std::move(profile));
        }
        else
        {
            *existing = std::move(profile);
        }
    }
    config.UserProfiles(std::move(profiles));
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
    std::vector<PeerConfig> peers = config.Peers();
    for (PeerConfig& peer : peers)
    {
        const std::string owner = OwnerName(config.UserProfiles(), peer.OwnerId());
        if (!owner.empty())
        {
            peer.Owner(owner);
        }
    }
    config.Peers(std::move(peers));
}

void ApplyDerpMetadata(PeerConfig& peer, const nlohmann::json& regions)
{
    if (peer.DerpRegion() == 0)
    {
        return;
    }
    const auto region = regions.find(std::format("{}", peer.DerpRegion()));
    if (region != regions.end())
    {
        peer.DerpCode(region->value("RegionCode", std::format("derp-{}", peer.DerpRegion())));
        peer.DerpHost(DerpHost(*region));
    }
}

void ApplyHostInfoMetadata(NetworkConfig& config, const nlohmann::json& node)
{
    if (!node.contains("Hostinfo") || !node.at("Hostinfo").is_object())
    {
        return;
    }
    const nlohmann::json& hostInfo = node.at("Hostinfo");
    config.SelfClientVersion(hostInfo.value("IPNVersion", ""));
    config.SelfWireIngress(hostInfo.value("WireIngress", false));
    config.SelfIngressEnabled(hostInfo.value("IngressEnabled", false));
    config.SelfPeerApi4Port(0);
    config.SelfPeerApi6Port(0);
    if (!hostInfo.contains("Services") || !hostInfo.at("Services").is_array())
    {
        return;
    }
    for (const nlohmann::json& service : hostInfo.at("Services"))
    {
        const std::string protocol = service.value("Proto", "");
        if (protocol == "peerapi4")
        {
            config.SelfPeerApi4Port(service.value("Port", 0));
        }
        else if (protocol == "peerapi6")
        {
            config.SelfPeerApi6Port(service.value("Port", 0));
        }
    }
}

PeerConfig Peer(const nlohmann::json& node,
                const nlohmann::json& regions,
                const std::vector<UserProfile>& profiles)
{
    const auto addressTexts = StringArray(node, "Addresses");
    PeerConfig peer;
    peer.NodeId(NodeId(node));
    peer.Name(node.value("Name", ""));
    peer.OwnerId(node.value("User", 0ULL));
    peer.Owner(OwnerName(profiles, peer.OwnerId()));
    std::vector<std::string> addresses;
    for (const std::string& address : addressTexts)
    {
        addresses.push_back(address.substr(0, address.find('/')));
    }
    if (!addresses.empty())
    {
        const auto ipv4 = std::find_if(addresses.begin(),
                                       addresses.end(),
                                       [](const std::string& address)
                                       {
                                           return address.find(':') == std::string::npos;
                                       });
        peer.Address(ipv4 == addresses.end() ? addresses.front() : *ipv4);
    }
    peer.Addresses(std::move(addresses));
    peer.Key(node.value("Key", ""));
    peer.DiscoKey(node.value("DiscoKey", ""));
    peer.Online(node.value("Online", false));
    peer.LastSeen(node.value("LastSeen", ""));
    peer.KeyExpiry(node.value("KeyExpiry", ""));
    if (node.contains("Hostinfo") && node.at("Hostinfo").is_object())
    {
        const nlohmann::json& hostInfo = node.at("Hostinfo");
        peer.OperatingSystem(hostInfo.value("OS", ""));
        peer.ClientVersion(hostInfo.value("IPNVersion", ""));
        peer.WireIngress(hostInfo.value("WireIngress", false));
        peer.IngressEnabled(hostInfo.value("IngressEnabled", false));
        if (hostInfo.contains("Services") && hostInfo.at("Services").is_array())
        {
            for (const nlohmann::json& service : hostInfo.at("Services"))
            {
                const std::string protocol = service.value("Proto", "");
                if (protocol == "peerapi4")
                {
                    peer.PeerApi4Port(service.value("Port", 0));
                }
                else if (protocol == "peerapi6")
                {
                    peer.PeerApi6Port(service.value("Port", 0));
                }
            }
        }
    }
    const std::string derp = node.value("DERP", "");
    const std::size_t colon = derp.rfind(':');
    if (colon != std::string::npos)
    {
        peer.DerpRegion(std::stoi(derp.substr(colon + 1)));
        ApplyDerpMetadata(peer, regions);
    }
    std::vector<std::string> endpoints;
    for (const std::string& endpoint : StringArray(node, "Endpoints"))
    {
        if (EndpointPreference(endpoint) < 100)
        {
            endpoints.push_back(endpoint);
        }
    }
    std::stable_sort(endpoints.begin(),
                     endpoints.end(),
                     [](const std::string& left, const std::string& right)
                     {
                         return EndpointPreference(left) < EndpointPreference(right);
                     });
    peer.Endpoints(std::move(endpoints));
    std::vector<std::string> allowed = StringArray(node, "AllowedIPs");
    allowed.insert(allowed.end(), addressTexts.begin(), addressTexts.end());
    std::vector<tailgate::net::packet::Ipv4Prefix> allowedPrefixes;
    for (const std::string& text : allowed)
    {
        const auto prefix = tailgate::net::packet::Ipv4Prefix::Parse(text);
        if (prefix && prefix->PrefixLength() == 0)
        {
            peer.ExitNodeOption(true);
        }
        else if (prefix)
        {
            allowedPrefixes.push_back(*prefix);
        }
    }
    peer.AllowedPrefixes(std::move(allowedPrefixes));
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

std::vector<PeerConfig>::iterator FindPeer(std::vector<PeerConfig>& peers, std::uint64_t nodeId)
{
    return std::find_if(peers.begin(),
                        peers.end(),
                        [nodeId](const PeerConfig& peer)
                        {
                            return peer.NodeId() == nodeId;
                        });
}

void ApplyDnsConfig(NetworkConfig& config, const nlohmann::json& dns)
{
    config.DnsDomains(DnsDomains(dns));
    config.CertDomains(StringArray(dns, "CertDomains"));
    std::vector<std::string> defaultResolvers =
        ResolverArray(dns.value("Resolvers", nlohmann::json::array()));
    if (defaultResolvers.empty())
    {
        defaultResolvers = ResolverArray(dns.value("FallbackResolvers", nlohmann::json::array()));
    }
    config.DnsDefaultResolvers(std::move(defaultResolvers));
    std::vector<NetworkConfig::DnsRoute> routes;
    for (const auto& [suffix, resolvers] : dns.at("Routes").items())
    {
        routes.push_back(
            NetworkConfig::DnsRoute{.Suffix = suffix, .Resolvers = ResolverArray(resolvers)});
    }
    config.DnsRoutes(std::move(routes));
}

} // namespace

NetworkConfig NetworkMapParser::Parse(const std::string& text)
{
    const nlohmann::json map = nlohmann::json::parse(text);
    NetworkConfig result;
    result.Domain(map.value("Domain", ""));
    (void)MergeUserProfiles(result, map);
    ApplyAccountMetadata(result, map);
    const nlohmann::json& node = map.at("Node");
    result.SelfNodeId(NodeId(node));
    result.SelfKey(node.value("Key", ""));
    result.SelfName(TrimTrailingDot(node.value("Name", "")));
    result.SelfMachineAuthorized(node.value("MachineAuthorized", false));
    result.MagicDnsDomain(MagicDnsDomainFromNodeName(result.SelfName()));
    result.Capabilities(Capabilities(map));
    ApplyHostInfoMetadata(result, node);
    std::vector<std::string> selfAddresses;
    for (const std::string& address : StringArray(node, "Addresses"))
    {
        selfAddresses.push_back(address.substr(0, address.find('/')));
    }
    const auto selfIpv4 =
        std::find_if(selfAddresses.begin(),
                     selfAddresses.end(),
                     [](const std::string& address)
                     {
                         return tailgate::net::Ipv4Address::TryParse(address).has_value();
                     });
    if (selfIpv4 != selfAddresses.end())
    {
        result.SelfAddress(*selfIpv4);
    }
    else if (!selfAddresses.empty())
    {
        result.SelfAddress(selfAddresses.front());
    }
    result.SelfAddresses(std::move(selfAddresses));
    const nlohmann::json& dns = map.at("DNSConfig");
    ApplyDnsConfig(result, dns);
    result.Peers(Peers(map, result.UserProfiles()));

    for (const std::string& resolverText : DnsResolvers(dns))
    {
        const auto resolver = tailgate::net::Ipv4Address::TryParse(resolverText);
        if (!resolver)
        {
            continue;
        }
        for (const PeerConfig& peer : result.Peers())
        {
            if (std::any_of(peer.AllowedPrefixes().begin(),
                            peer.AllowedPrefixes().end(),
                            [&](const tailgate::net::packet::Ipv4Prefix& prefix)
                            {
                                return prefix.Contains(resolver->HostOrder());
                            }))
            {
                result.DnsResolver(resolverText);
                result.DerpRegion(peer.DerpRegion());
                break;
            }
        }
        if (!result.DnsResolver().empty())
        {
            break;
        }
    }
    if (result.DnsResolver().empty())
    {
        throw std::runtime_error("Network map did not provide a reachable IPv4 DNS resolver.");
    }
    if (result.DerpRegion() == 0)
    {
        const auto peer = std::find_if(result.Peers().begin(),
                                       result.Peers().end(),
                                       [](const PeerConfig& value)
                                       {
                                           return value.DerpRegion() != 0;
                                       });
        if (peer == result.Peers().end())
        {
            throw std::runtime_error("Network map did not provide a DERP region.");
        }
        result.DerpRegion(peer->DerpRegion());
    }
    const nlohmann::json& region =
        map.at("DERPMap").at("Regions").at(std::format("{}", result.DerpRegion()));
    result.DerpCode(region.value("RegionCode", std::format("derp-{}", result.DerpRegion())));
    result.DerpHost(DerpHost(region));
    const auto [stunHost, stunPort] = StunEndpoint(region);
    result.StunHost(stunHost);
    result.StunPort(stunPort);
    if (result.DerpHost().empty())
    {
        throw std::runtime_error("Selected DERP region has no usable hostname.");
    }
    return result;
}

bool NetworkMapParser::ApplyUpdate(NetworkConfig& config, const std::string& text)
{
    const nlohmann::json map = nlohmann::json::parse(text);
    config.RemovedPeerNodeIds({});
    if (map.value("KeepAlive", false))
    {
        return false;
    }

    std::vector<PeerConfig> peers = config.Peers();
    std::vector<std::uint64_t> removedPeerNodeIds;
    bool changed = false;
    if (map.contains("Domain"))
    {
        config.Domain(map.value("Domain", ""));
        changed = true;
    }
    const bool userProfilesChanged = MergeUserProfiles(config, map);
    if (map.contains("Node") || userProfilesChanged)
    {
        if (map.contains("Node") && map.at("Node").is_object() && map.at("Node").contains("Name"))
        {
            config.SelfName(TrimTrailingDot(map.at("Node").value("Name", "")));
            config.SelfKey(map.at("Node").value("Key", config.SelfKey()));
            config.MagicDnsDomain(MagicDnsDomainFromNodeName(config.SelfName()));
        }
        if (map.contains("Node") && map.at("Node").is_object() &&
            map.at("Node").contains("MachineAuthorized"))
        {
            config.SelfMachineAuthorized(map.at("Node").value("MachineAuthorized", false));
        }
        if (map.contains("Node") && map.at("Node").is_object() && map.at("Node").contains("CapMap"))
        {
            config.Capabilities(Capabilities(map));
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
        const auto homeRegion = updateRegions.find(std::format("{}", config.DerpRegion()));
        if (homeRegion != updateRegions.end())
        {
            config.DerpCode(
                homeRegion->value("RegionCode", std::format("derp-{}", config.DerpRegion())));
            config.DerpHost(DerpHost(*homeRegion));
            const auto [stunHost, stunPort] = StunEndpoint(*homeRegion);
            config.StunHost(stunHost);
            config.StunPort(stunPort);
        }
        for (PeerConfig& peer : peers)
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
            removedPeerNodeIds.push_back(nodeId);
            peers.erase(std::remove_if(peers.begin(),
                                       peers.end(),
                                       [nodeId](const PeerConfig& peer)
                                       {
                                           return peer.NodeId() == nodeId;
                                       }),
                        peers.end());
        }
        changed = true;
    }
    if (map.contains("PeersChanged"))
    {
        for (const nlohmann::json& node : map.at("PeersChanged"))
        {
            PeerConfig peer = Peer(node, updateRegions, config.UserProfiles());
            auto existing = FindPeer(peers, peer.NodeId());
            if (existing == peers.end())
            {
                peers.push_back(std::move(peer));
            }
            else
            {
                if (peer.DerpRegion() == existing->DerpRegion() && peer.DerpCode().empty())
                {
                    peer.DerpCode(existing->DerpCode());
                    peer.DerpHost(existing->DerpHost());
                }
                if (peer.Owner().empty())
                {
                    // Incremental updates usually omit UserProfiles; keep the known owner.
                    peer.Owner(existing->Owner());
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
            auto peer = FindPeer(peers, std::stoull(id));
            if (peer != peers.end())
            {
                peer->Online(online.get<bool>());
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
            auto peer = FindPeer(peers, std::stoull(id));
            if (peer != peers.end())
            {
                peer->LastSeen(seen.get<bool>() ? CurrentRfc3339Time() : std::string());
                changed = true;
            }
        }
    }
    if (map.contains("PeersChangedPatch"))
    {
        for (const nlohmann::json& patch : map.at("PeersChangedPatch"))
        {
            auto peer = FindPeer(peers, patch.value("NodeID", 0ULL));
            if (peer == peers.end())
            {
                continue;
            }
            if (patch.contains("DERPRegion"))
            {
                peer->DerpRegion(patch.at("DERPRegion").get<int>());
                peer->DerpCode({});
                peer->DerpHost({});
                ApplyDerpMetadata(*peer, updateRegions);
            }
            if (patch.contains("Endpoints"))
            {
                std::vector<std::string> endpoints;
                for (const std::string& endpoint :
                     patch.at("Endpoints").get<std::vector<std::string>>())
                {
                    if (EndpointPreference(endpoint) < 100)
                    {
                        endpoints.push_back(endpoint);
                    }
                }
                std::stable_sort(endpoints.begin(),
                                 endpoints.end(),
                                 [](const std::string& left, const std::string& right)
                                 {
                                     return EndpointPreference(left) < EndpointPreference(right);
                                 });
                peer->Endpoints(std::move(endpoints));
            }
            if (patch.contains("Key"))
            {
                if (std::optional<std::string> key = KeyText(patch.at("Key"), "nodekey:"))
                {
                    peer->Key(*key);
                }
            }
            if (patch.contains("DiscoKey"))
            {
                if (std::optional<std::string> key = KeyText(patch.at("DiscoKey"), "discokey:"))
                {
                    peer->DiscoKey(*key);
                }
            }
            if (patch.contains("Online") && patch.at("Online").is_boolean())
            {
                peer->Online(patch.at("Online").get<bool>());
            }
            if (patch.contains("LastSeen"))
            {
                peer->LastSeen(TimeText(patch.at("LastSeen")));
            }
            if (patch.contains("KeyExpiry"))
            {
                peer->KeyExpiry(TimeText(patch.at("KeyExpiry")));
            }
            // Cap and CapMap changes are intentionally not modeled: Tailgate consumes no
            // per-peer capability metadata.
            changed = true;
        }
    }
    config.Peers(std::move(peers));
    config.RemovedPeerNodeIds(std::move(removedPeerNodeIds));
    if (userProfilesChanged)
    {
        RefreshPeerOwners(config);
    }
    return changed;
}

} // namespace tailgate::control::client
