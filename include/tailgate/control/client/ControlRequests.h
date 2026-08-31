#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tailgate::control::client
{

struct HostService
{
    std::string Protocol;
    int Port = 0;
};

class HostInfo
{
public:
    HostInfo() = default;
    HostInfo(std::string hostname,
             std::string operatingSystem,
             std::string operatingSystemVersion,
             std::string architecture);

    void ApplySessionConfig(HostInfo config);
    void SetHostname(std::string hostname);
    void SetClientMetadata(std::string clientVersion,
                           std::string frontendLogId,
                           std::string backendLogId);
    void AddService(HostService service);
    void SetIngress(bool wireIngress, bool ingressEnabled) noexcept;

    [[nodiscard]] const std::string& Hostname() const noexcept;
    [[nodiscard]] const std::string& OperatingSystem() const noexcept;
    [[nodiscard]] const std::string& OperatingSystemVersion() const noexcept;
    [[nodiscard]] const std::string& Architecture() const noexcept;
    [[nodiscard]] const std::string& ClientVersion() const noexcept;
    [[nodiscard]] const std::string& FrontendLogId() const noexcept;
    [[nodiscard]] const std::string& BackendLogId() const noexcept;
    [[nodiscard]] const std::vector<HostService>& Services() const noexcept;
    [[nodiscard]] bool WireIngress() const noexcept;
    [[nodiscard]] bool IngressEnabled() const noexcept;
    [[nodiscard]] bool NetInfoMappingVariesByDestIp() const noexcept;
    [[nodiscard]] bool NetInfoWorkingIpv6() const noexcept;
    [[nodiscard]] bool NetInfoOsHasIpv6() const noexcept;
    [[nodiscard]] bool NetInfoWorkingUdp() const noexcept;
    [[nodiscard]] bool NetInfoWorkingIcmpV4() const noexcept;
    [[nodiscard]] bool NetInfoUpnp() const noexcept;
    [[nodiscard]] bool NetInfoPmp() const noexcept;
    [[nodiscard]] bool NetInfoPcp() const noexcept;
    [[nodiscard]] const std::string& NetInfoFirewallMode() const noexcept;

private:
    std::string m_hostname;
    std::string m_operatingSystem;
    std::string m_operatingSystemVersion;
    std::string m_architecture;
    std::string m_clientVersion = "Tailgate";
    std::string m_frontendLogId;
    std::string m_backendLogId;
    std::vector<HostService> m_services;
    bool m_wireIngress = false;
    bool m_ingressEnabled = false;
    bool m_netInfoMappingVariesByDestIp = false;
    bool m_netInfoWorkingIpv6 = false;
    bool m_netInfoOsHasIpv6 = true;
    bool m_netInfoWorkingUdp = true;
    bool m_netInfoWorkingIcmpV4 = false;
    bool m_netInfoUpnp = false;
    bool m_netInfoPmp = false;
    bool m_netInfoPcp = false;
    std::string m_netInfoFirewallMode = "ipt-default";
};

enum class EndpointType : int
{
    Unknown = 0,
    Local = 1,
    Stun = 2,
    Portmapped = 3,
    Stun4LocalPort = 4,
    ExplicitConf = 5,
};

struct MapEndpoint
{
    std::string AddressPort;
    EndpointType Type = EndpointType::Unknown;
};

class RegisterResponse
{
public:
    [[nodiscard]] static std::optional<RegisterResponse>
    Parse(const std::vector<std::uint8_t>& response);

    [[nodiscard]] bool MachineAuthorized() const noexcept;
    [[nodiscard]] bool NodeKeyExpired() const noexcept;
    [[nodiscard]] const std::string& AuthUrl() const noexcept;
    [[nodiscard]] const std::string& Error() const noexcept;

private:
    bool m_machineAuthorized = false;
    bool m_nodeKeyExpired = false;
    std::string m_authUrl;
    std::string m_error;
};

class ControlRequest final
{
public:
    [[nodiscard]] static std::vector<std::uint8_t>
    BuildRegister(const std::string& nodeKey, const std::string& authKey, const HostInfo& host);
    [[nodiscard]] static std::vector<std::uint8_t> BuildRegister(const std::string& nodeKey,
                                                                 const std::string& authKey,
                                                                 const std::string& followupUrl,
                                                                 const HostInfo& host);
    [[nodiscard]] static std::vector<std::uint8_t>
    BuildMap(const std::string& nodeKey,
             const std::string& discoKey,
             const HostInfo& host,
             int preferredDerp = 0,
             bool stream = false,
             bool omitPeers = false,
             const std::vector<MapEndpoint>& endpoints = {},
             bool keepAlive = true);
    [[nodiscard]] static std::vector<std::uint8_t>
    BuildReadOnlyMap(const std::string& nodeKey, const std::string& discoKey, const HostInfo& host);
    [[nodiscard]] static std::vector<std::uint8_t> BuildLogout(const std::string& nodeKey,
                                                               const HostInfo& host);
    [[nodiscard]] static std::vector<std::uint8_t> BuildQueryFeature(const std::string& nodeKey,
                                                                     const std::string& feature);
    [[nodiscard]] static std::vector<std::uint8_t>
    BuildSetDns(const std::string& nodeKey, const std::string& name, const std::string& value);
};

[[nodiscard]] bool IsValidAuthorizationUrl(std::string_view url);
[[nodiscard]] std::string AuthorizationCode(std::string_view url);
[[nodiscard]] std::string MachineApprovalUrl(std::string_view address);

[[nodiscard]] bool IsRetryableInitialMapError(int status, std::string_view response);

} // namespace tailgate::control::client
