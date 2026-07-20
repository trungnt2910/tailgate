#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace tailgate::protocol
{

struct HostService
{
    std::string Protocol;
    int Port = 0;
};

struct HostInfo
{
    std::string Hostname;
    std::string OperatingSystem;
    std::string OperatingSystemVersion;
    std::string Architecture;
    std::string ClientVersion = "Tailgate";
    std::string FrontendLogId;
    std::string BackendLogId;
    std::vector<HostService> Services{};
    bool WireIngress = false;
    bool IngressEnabled = false;
    bool NetInfoMappingVariesByDestIp = false;
    bool NetInfoWorkingIpv6 = false;
    bool NetInfoOsHasIpv6 = true;
    bool NetInfoWorkingUdp = true;
    bool NetInfoWorkingIcmpV4 = false;
    bool NetInfoUpnp = false;
    bool NetInfoPmp = false;
    bool NetInfoPcp = false;
    std::string NetInfoFirewallMode = "ipt-default";
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

struct RegisterResponse
{
    bool MachineAuthorized = false;
    bool NodeKeyExpired = false;
    std::string AuthUrl;
    std::string Error;
};

[[nodiscard]] std::vector<std::uint8_t>
BuildRegisterRequest(const std::string& nodeKey, const std::string& authKey, const HostInfo& host);

[[nodiscard]] std::vector<std::uint8_t> BuildRegisterRequest(const std::string& nodeKey,
                                                             const std::string& authKey,
                                                             const std::string& followupUrl,
                                                             const HostInfo& host);

[[nodiscard]] std::optional<RegisterResponse>
ParseRegisterResponse(const std::vector<std::uint8_t>& response);

[[nodiscard]] bool IsValidAuthorizationUrl(std::string_view url);
[[nodiscard]] std::string AuthorizationCode(std::string_view url);
[[nodiscard]] std::string MachineApprovalUrl(std::string_view address);

[[nodiscard]] bool IsRetryableInitialMapError(int status, std::string_view response);

[[nodiscard]] std::vector<std::uint8_t>
BuildMapRequest(const std::string& nodeKey,
                const std::string& discoKey,
                const HostInfo& host,
                int preferredDerp = 0,
                bool stream = false,
                bool omitPeers = false,
                const std::vector<MapEndpoint>& endpoints = {},
                bool keepAlive = true);

[[nodiscard]] std::vector<std::uint8_t> BuildReadOnlyMapRequest(const std::string& nodeKey,
                                                                const std::string& discoKey,
                                                                const HostInfo& host);

[[nodiscard]] std::vector<std::uint8_t> BuildLogoutRequest(const std::string& nodeKey,
                                                           const HostInfo& host);

[[nodiscard]] std::vector<std::uint8_t> BuildQueryFeatureRequest(const std::string& nodeKey,
                                                                 const std::string& feature);
[[nodiscard]] std::vector<std::uint8_t>
BuildSetDnsRequest(const std::string& nodeKey, const std::string& name, const std::string& value);

} // namespace tailgate::protocol
