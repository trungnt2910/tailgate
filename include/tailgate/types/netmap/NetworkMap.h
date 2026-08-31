#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <tailgate/net/packet/Ipv4.h>

namespace tailgate::types::netmap
{

struct UserProfile
{
    std::uint64_t Id = 0;
    std::string LoginName;
    std::string DisplayName;
    std::string ProfilePicUrl;
};

class PeerConfig final
{
public:
    void NodeId(std::uint64_t nodeId) noexcept
    {
        m_nodeId = nodeId;
    }

    [[nodiscard]] std::uint64_t NodeId() const noexcept
    {
        return m_nodeId;
    }

    void OwnerId(std::uint64_t ownerId) noexcept
    {
        m_ownerId = ownerId;
    }

    [[nodiscard]] std::uint64_t OwnerId() const noexcept
    {
        return m_ownerId;
    }

    void Name(std::string name)
    {
        m_name = std::move(name);
    }

    [[nodiscard]] const std::string& Name() const noexcept
    {
        return m_name;
    }

    void Address(std::string address)
    {
        m_address = std::move(address);
    }

    [[nodiscard]] const std::string& Address() const noexcept
    {
        return m_address;
    }

    void Addresses(std::vector<std::string> addresses)
    {
        m_addresses = std::move(addresses);
    }

    [[nodiscard]] const std::vector<std::string>& Addresses() const noexcept
    {
        return m_addresses;
    }

    void Key(std::string key)
    {
        m_key = std::move(key);
    }

    [[nodiscard]] const std::string& Key() const noexcept
    {
        return m_key;
    }

    void DiscoKey(std::string discoKey)
    {
        m_discoKey = std::move(discoKey);
    }

    [[nodiscard]] const std::string& DiscoKey() const noexcept
    {
        return m_discoKey;
    }

    void Endpoints(std::vector<std::string> endpoints)
    {
        m_endpoints = std::move(endpoints);
    }

    [[nodiscard]] const std::vector<std::string>& Endpoints() const noexcept
    {
        return m_endpoints;
    }

    void AllowedPrefixes(std::vector<tailgate::net::packet::Ipv4Prefix> allowedPrefixes)
    {
        m_allowedPrefixes = std::move(allowedPrefixes);
    }

    [[nodiscard]] const std::vector<tailgate::net::packet::Ipv4Prefix>&
    AllowedPrefixes() const noexcept
    {
        return m_allowedPrefixes;
    }

    void DerpRegion(int derpRegion) noexcept
    {
        m_derpRegion = derpRegion;
    }

    [[nodiscard]] int DerpRegion() const noexcept
    {
        return m_derpRegion;
    }

    void DerpCode(std::string derpCode)
    {
        m_derpCode = std::move(derpCode);
    }

    [[nodiscard]] const std::string& DerpCode() const noexcept
    {
        return m_derpCode;
    }

    void DerpHost(std::string derpHost)
    {
        m_derpHost = std::move(derpHost);
    }

    [[nodiscard]] const std::string& DerpHost() const noexcept
    {
        return m_derpHost;
    }

    void OperatingSystem(std::string operatingSystem)
    {
        m_operatingSystem = std::move(operatingSystem);
    }

    [[nodiscard]] const std::string& OperatingSystem() const noexcept
    {
        return m_operatingSystem;
    }

    void ClientVersion(std::string clientVersion)
    {
        m_clientVersion = std::move(clientVersion);
    }

    [[nodiscard]] const std::string& ClientVersion() const noexcept
    {
        return m_clientVersion;
    }

    void Owner(std::string owner)
    {
        m_owner = std::move(owner);
    }

    [[nodiscard]] const std::string& Owner() const noexcept
    {
        return m_owner;
    }

    void PeerApi4Port(int peerApi4Port) noexcept
    {
        m_peerApi4Port = peerApi4Port;
    }

    [[nodiscard]] int PeerApi4Port() const noexcept
    {
        return m_peerApi4Port;
    }

    void PeerApi6Port(int peerApi6Port) noexcept
    {
        m_peerApi6Port = peerApi6Port;
    }

    [[nodiscard]] int PeerApi6Port() const noexcept
    {
        return m_peerApi6Port;
    }

    void WireIngress(bool wireIngress) noexcept
    {
        m_wireIngress = wireIngress;
    }

    [[nodiscard]] bool WireIngress() const noexcept
    {
        return m_wireIngress;
    }

    void IngressEnabled(bool ingressEnabled) noexcept
    {
        m_ingressEnabled = ingressEnabled;
    }

    [[nodiscard]] bool IngressEnabled() const noexcept
    {
        return m_ingressEnabled;
    }

    void Online(bool online) noexcept
    {
        m_online = online;
    }

    [[nodiscard]] bool Online() const noexcept
    {
        return m_online;
    }

    void ExitNodeOption(bool exitNodeOption) noexcept
    {
        m_exitNodeOption = exitNodeOption;
    }

    [[nodiscard]] bool ExitNodeOption() const noexcept
    {
        return m_exitNodeOption;
    }

    void LastSeen(std::string lastSeen)
    {
        m_lastSeen = std::move(lastSeen);
    }

    [[nodiscard]] const std::string& LastSeen() const noexcept
    {
        return m_lastSeen;
    }

    void KeyExpiry(std::string keyExpiry)
    {
        m_keyExpiry = std::move(keyExpiry);
    }

    [[nodiscard]] const std::string& KeyExpiry() const noexcept
    {
        return m_keyExpiry;
    }

    [[nodiscard]] bool MatchesTarget(const std::string& nameOrAddress) const;
    [[nodiscard]] std::string DisplayName() const;

private:
    std::uint64_t m_nodeId = 0;
    std::uint64_t m_ownerId = 0;
    std::string m_name;
    std::string m_address;
    std::vector<std::string> m_addresses;
    std::string m_key;
    std::string m_discoKey;
    std::vector<std::string> m_endpoints;
    std::vector<tailgate::net::packet::Ipv4Prefix> m_allowedPrefixes;
    int m_derpRegion = 0;
    std::string m_derpCode;
    std::string m_derpHost;
    std::string m_operatingSystem;
    std::string m_clientVersion;
    std::string m_owner;
    int m_peerApi4Port = 0;
    int m_peerApi6Port = 0;
    bool m_wireIngress = false;
    bool m_ingressEnabled = false;
    bool m_online = false;
    bool m_exitNodeOption = false;
    std::string m_lastSeen;
    std::string m_keyExpiry;
};

class NetworkConfig final
{
public:
    struct DnsRoute
    {
        std::string Suffix;
        std::vector<std::string> Resolvers;
    };

    void SelfNodeId(std::uint64_t selfNodeId) noexcept
    {
        m_selfNodeId = selfNodeId;
    }

    [[nodiscard]] std::uint64_t SelfNodeId() const noexcept
    {
        return m_selfNodeId;
    }

    void SelfKey(std::string selfKey)
    {
        m_selfKey = std::move(selfKey);
    }

    [[nodiscard]] const std::string& SelfKey() const noexcept
    {
        return m_selfKey;
    }

    void SelfAddress(std::string selfAddress)
    {
        m_selfAddress = std::move(selfAddress);
    }

    [[nodiscard]] const std::string& SelfAddress() const noexcept
    {
        return m_selfAddress;
    }

    void SelfAddresses(std::vector<std::string> selfAddresses)
    {
        m_selfAddresses = std::move(selfAddresses);
    }

    [[nodiscard]] const std::vector<std::string>& SelfAddresses() const noexcept
    {
        return m_selfAddresses;
    }

    void SelfName(std::string selfName)
    {
        m_selfName = std::move(selfName);
    }

    [[nodiscard]] const std::string& SelfName() const noexcept
    {
        return m_selfName;
    }

    void SelfMachineAuthorized(bool selfMachineAuthorized) noexcept
    {
        m_selfMachineAuthorized = selfMachineAuthorized;
    }

    [[nodiscard]] bool SelfMachineAuthorized() const noexcept
    {
        return m_selfMachineAuthorized;
    }

    void Domain(std::string domain)
    {
        m_domain = std::move(domain);
    }

    [[nodiscard]] const std::string& Domain() const noexcept
    {
        return m_domain;
    }

    void MagicDnsDomain(std::string magicDnsDomain)
    {
        m_magicDnsDomain = std::move(magicDnsDomain);
    }

    [[nodiscard]] const std::string& MagicDnsDomain() const noexcept
    {
        return m_magicDnsDomain;
    }

    void TailnetDisplayName(std::string tailnetDisplayName)
    {
        m_tailnetDisplayName = std::move(tailnetDisplayName);
    }

    [[nodiscard]] const std::string& TailnetDisplayName() const noexcept
    {
        return m_tailnetDisplayName;
    }

    void AccountName(std::string accountName)
    {
        m_accountName = std::move(accountName);
    }

    [[nodiscard]] const std::string& AccountName() const noexcept
    {
        return m_accountName;
    }

    void AccountDisplayName(std::string accountDisplayName)
    {
        m_accountDisplayName = std::move(accountDisplayName);
    }

    [[nodiscard]] const std::string& AccountDisplayName() const noexcept
    {
        return m_accountDisplayName;
    }

    void AccountProfilePicUrl(std::string accountProfilePicUrl)
    {
        m_accountProfilePicUrl = std::move(accountProfilePicUrl);
    }

    [[nodiscard]] const std::string& AccountProfilePicUrl() const noexcept
    {
        return m_accountProfilePicUrl;
    }

    void Capabilities(std::vector<std::string> capabilities)
    {
        m_capabilities = std::move(capabilities);
    }

    [[nodiscard]] const std::vector<std::string>& Capabilities() const noexcept
    {
        return m_capabilities;
    }

    void SelfClientVersion(std::string selfClientVersion)
    {
        m_selfClientVersion = std::move(selfClientVersion);
    }

    [[nodiscard]] const std::string& SelfClientVersion() const noexcept
    {
        return m_selfClientVersion;
    }

    void SelfPeerApi4Port(int selfPeerApi4Port) noexcept
    {
        m_selfPeerApi4Port = selfPeerApi4Port;
    }

    [[nodiscard]] int SelfPeerApi4Port() const noexcept
    {
        return m_selfPeerApi4Port;
    }

    void SelfPeerApi6Port(int selfPeerApi6Port) noexcept
    {
        m_selfPeerApi6Port = selfPeerApi6Port;
    }

    [[nodiscard]] int SelfPeerApi6Port() const noexcept
    {
        return m_selfPeerApi6Port;
    }

    void SelfWireIngress(bool selfWireIngress) noexcept
    {
        m_selfWireIngress = selfWireIngress;
    }

    [[nodiscard]] bool SelfWireIngress() const noexcept
    {
        return m_selfWireIngress;
    }

    void SelfIngressEnabled(bool selfIngressEnabled) noexcept
    {
        m_selfIngressEnabled = selfIngressEnabled;
    }

    [[nodiscard]] bool SelfIngressEnabled() const noexcept
    {
        return m_selfIngressEnabled;
    }

    void DnsResolver(std::string dnsResolver)
    {
        m_dnsResolver = std::move(dnsResolver);
    }

    [[nodiscard]] const std::string& DnsResolver() const noexcept
    {
        return m_dnsResolver;
    }

    void DnsDomains(std::vector<std::string> dnsDomains)
    {
        m_dnsDomains = std::move(dnsDomains);
    }

    [[nodiscard]] const std::vector<std::string>& DnsDomains() const noexcept
    {
        return m_dnsDomains;
    }

    void CertDomains(std::vector<std::string> certDomains)
    {
        m_certDomains = std::move(certDomains);
    }

    [[nodiscard]] const std::vector<std::string>& CertDomains() const noexcept
    {
        return m_certDomains;
    }

    void DnsDefaultResolvers(std::vector<std::string> dnsDefaultResolvers)
    {
        m_dnsDefaultResolvers = std::move(dnsDefaultResolvers);
    }

    [[nodiscard]] const std::vector<std::string>& DnsDefaultResolvers() const noexcept
    {
        return m_dnsDefaultResolvers;
    }

    void DnsRoutes(std::vector<DnsRoute> dnsRoutes)
    {
        m_dnsRoutes = std::move(dnsRoutes);
    }

    [[nodiscard]] const std::vector<DnsRoute>& DnsRoutes() const noexcept
    {
        return m_dnsRoutes;
    }

    void DerpRegion(int derpRegion) noexcept
    {
        m_derpRegion = derpRegion;
    }

    [[nodiscard]] int DerpRegion() const noexcept
    {
        return m_derpRegion;
    }

    void DerpHost(std::string derpHost)
    {
        m_derpHost = std::move(derpHost);
    }

    [[nodiscard]] const std::string& DerpHost() const noexcept
    {
        return m_derpHost;
    }

    void DerpCode(std::string derpCode)
    {
        m_derpCode = std::move(derpCode);
    }

    [[nodiscard]] const std::string& DerpCode() const noexcept
    {
        return m_derpCode;
    }

    void StunHost(std::string stunHost)
    {
        m_stunHost = std::move(stunHost);
    }

    [[nodiscard]] const std::string& StunHost() const noexcept
    {
        return m_stunHost;
    }

    void StunPort(int stunPort) noexcept
    {
        m_stunPort = stunPort;
    }

    [[nodiscard]] int StunPort() const noexcept
    {
        return m_stunPort;
    }

    void UserProfiles(std::vector<UserProfile> userProfiles)
    {
        m_userProfiles = std::move(userProfiles);
    }

    [[nodiscard]] const std::vector<UserProfile>& UserProfiles() const noexcept
    {
        return m_userProfiles;
    }

    void Peers(std::vector<PeerConfig> peers)
    {
        m_peers = std::move(peers);
    }

    [[nodiscard]] const std::vector<PeerConfig>& Peers() const noexcept
    {
        return m_peers;
    }

    void RemovedPeerNodeIds(std::vector<std::uint64_t> removedPeerNodeIds)
    {
        m_removedPeerNodeIds = std::move(removedPeerNodeIds);
    }

    [[nodiscard]] const std::vector<std::uint64_t>& RemovedPeerNodeIds() const noexcept
    {
        return m_removedPeerNodeIds;
    }

    [[nodiscard]] std::optional<std::size_t>
    FindRoute(std::uint32_t destination, std::optional<std::size_t> exitNode = std::nullopt) const;
    [[nodiscard]] std::optional<std::size_t> FindPeer(const std::string& nameOrAddress,
                                                      bool requireOnline = false) const;
    [[nodiscard]] std::optional<std::size_t> FindExitNode(const std::string& nameOrAddress,
                                                          bool requireOnline = false) const;
    [[nodiscard]] std::string DerpCodeForRegion(int region) const;
    [[nodiscard]] bool HasCapability(const std::string& capability) const;
    [[nodiscard]] bool AllowsFunnelPort(int port) const;
    [[nodiscard]] std::string DisplayName() const;
    [[nodiscard]] std::string FirstIpv6Address() const;
    [[nodiscard]] std::string CapabilitySummary() const;

private:
    std::uint64_t m_selfNodeId = 0;
    std::string m_selfKey;
    std::string m_selfAddress;
    std::vector<std::string> m_selfAddresses;
    std::string m_selfName;
    bool m_selfMachineAuthorized = false;
    std::string m_domain;
    std::string m_magicDnsDomain;
    std::string m_tailnetDisplayName;
    std::string m_accountName;
    std::string m_accountDisplayName;
    std::string m_accountProfilePicUrl;
    std::vector<std::string> m_capabilities;
    std::string m_selfClientVersion;
    int m_selfPeerApi4Port = 0;
    int m_selfPeerApi6Port = 0;
    bool m_selfWireIngress = false;
    bool m_selfIngressEnabled = false;
    std::string m_dnsResolver;
    std::vector<std::string> m_dnsDomains;
    std::vector<std::string> m_certDomains;
    std::vector<std::string> m_dnsDefaultResolvers;
    std::vector<DnsRoute> m_dnsRoutes;
    int m_derpRegion = 0;
    std::string m_derpHost;
    std::string m_derpCode;
    std::string m_stunHost;
    int m_stunPort = 3478;
    std::vector<UserProfile> m_userProfiles;
    std::vector<PeerConfig> m_peers;
    std::vector<std::uint64_t> m_removedPeerNodeIds;
};

} // namespace tailgate::types::netmap
