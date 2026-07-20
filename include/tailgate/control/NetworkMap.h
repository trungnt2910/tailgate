#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <tailgate/network/Ipv4.h>

namespace tailgate::control
{

struct UserProfile
{
    std::uint64_t Id = 0;
    std::string LoginName;
    std::string DisplayName;
    std::string ProfilePicUrl;
};

struct PeerConfig
{
    std::uint64_t NodeId = 0;
    std::uint64_t OwnerId = 0;
    std::string Name;
    std::string Address;
    std::vector<std::string> Addresses;
    std::string Key;
    std::string DiscoKey;
    std::vector<std::string> Endpoints;
    std::vector<network::Ipv4Prefix> AllowedPrefixes;
    int DerpRegion = 0;
    std::string DerpCode;
    std::string DerpHost;
    std::string OperatingSystem;
    std::string ClientVersion;
    std::string Owner;
    int PeerApi4Port = 0;
    int PeerApi6Port = 0;
    bool WireIngress = false;
    bool IngressEnabled = false;
    bool Online = false;
    bool ExitNodeOption = false;
    // RFC 3339 timestamps as sent by control; empty when control has not reported them.
    std::string LastSeen;
    std::string KeyExpiry;
};

struct NetworkConfig
{
    struct DnsRoute
    {
        std::string Suffix;
        std::vector<std::string> Resolvers;
    };

    std::uint64_t SelfNodeId = 0;
    std::string SelfKey;
    std::string SelfAddress;
    std::vector<std::string> SelfAddresses;
    std::string SelfName;
    bool SelfMachineAuthorized = false;
    std::string Domain;
    std::string MagicDnsDomain;
    std::string TailnetDisplayName;
    std::string AccountName;
    std::string AccountDisplayName;
    std::string AccountProfilePicUrl;
    std::vector<std::string> Capabilities;
    std::string SelfClientVersion;
    int SelfPeerApi4Port = 0;
    int SelfPeerApi6Port = 0;
    bool SelfWireIngress = false;
    bool SelfIngressEnabled = false;
    std::string DnsResolver;
    std::vector<std::string> DnsDomains;
    std::vector<std::string> CertDomains;
    std::vector<std::string> DnsDefaultResolvers;
    std::vector<DnsRoute> DnsRoutes;
    int DerpRegion = 0;
    std::string DerpHost;
    std::string DerpCode;
    std::string StunHost;
    int StunPort = 3478;
    std::vector<UserProfile> UserProfiles;
    std::vector<PeerConfig> Peers;
    std::vector<std::uint64_t> RemovedPeerNodeIds;
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
[[nodiscard]] bool HasCapability(const NetworkConfig& config, const std::string& capability);
[[nodiscard]] bool AllowsFunnelPort(const NetworkConfig& config, int port);

} // namespace tailgate::control
