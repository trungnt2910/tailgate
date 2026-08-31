#include "tailgate/control/client/ControlRequests.h"

#include <algorithm>
#include <cctype>
#include <iterator>
#include <utility>

#include <boost/algorithm/string/case_conv.hpp>
#include <nlohmann/json.hpp>

namespace tailgate::control::client
{

HostInfo::HostInfo(std::string hostname,
                   std::string operatingSystem,
                   std::string operatingSystemVersion,
                   std::string architecture)
    : m_hostname(std::move(hostname)),
      m_operatingSystem(std::move(operatingSystem)),
      m_operatingSystemVersion(std::move(operatingSystemVersion)),
      m_architecture(std::move(architecture))
{
}

void HostInfo::ApplySessionConfig(HostInfo config)
{
    if (!config.m_hostname.empty())
    {
        m_hostname = std::move(config.m_hostname);
    }
    m_services.insert(m_services.end(),
                      std::make_move_iterator(config.m_services.begin()),
                      std::make_move_iterator(config.m_services.end()));
    m_wireIngress = m_wireIngress || config.m_wireIngress;
    m_ingressEnabled = m_ingressEnabled || config.m_ingressEnabled;
}

void HostInfo::SetHostname(std::string hostname)
{
    m_hostname = std::move(hostname);
}

void HostInfo::SetClientMetadata(std::string clientVersion,
                                 std::string frontendLogId,
                                 std::string backendLogId)
{
    m_clientVersion = std::move(clientVersion);
    m_frontendLogId = std::move(frontendLogId);
    m_backendLogId = std::move(backendLogId);
}

void HostInfo::AddService(HostService service)
{
    m_services.push_back(std::move(service));
}

void HostInfo::SetIngress(bool wireIngress, bool ingressEnabled) noexcept
{
    m_wireIngress = wireIngress;
    m_ingressEnabled = ingressEnabled;
}

const std::string& HostInfo::Hostname() const noexcept
{
    return m_hostname;
}

const std::string& HostInfo::OperatingSystem() const noexcept
{
    return m_operatingSystem;
}

const std::string& HostInfo::OperatingSystemVersion() const noexcept
{
    return m_operatingSystemVersion;
}

const std::string& HostInfo::Architecture() const noexcept
{
    return m_architecture;
}

const std::string& HostInfo::ClientVersion() const noexcept
{
    return m_clientVersion;
}

const std::string& HostInfo::FrontendLogId() const noexcept
{
    return m_frontendLogId;
}

const std::string& HostInfo::BackendLogId() const noexcept
{
    return m_backendLogId;
}

const std::vector<HostService>& HostInfo::Services() const noexcept
{
    return m_services;
}

bool HostInfo::WireIngress() const noexcept
{
    return m_wireIngress;
}

bool HostInfo::IngressEnabled() const noexcept
{
    return m_ingressEnabled;
}

bool HostInfo::NetInfoMappingVariesByDestIp() const noexcept
{
    return m_netInfoMappingVariesByDestIp;
}

bool HostInfo::NetInfoWorkingIpv6() const noexcept
{
    return m_netInfoWorkingIpv6;
}

bool HostInfo::NetInfoOsHasIpv6() const noexcept
{
    return m_netInfoOsHasIpv6;
}

bool HostInfo::NetInfoWorkingUdp() const noexcept
{
    return m_netInfoWorkingUdp;
}

bool HostInfo::NetInfoWorkingIcmpV4() const noexcept
{
    return m_netInfoWorkingIcmpV4;
}

bool HostInfo::NetInfoUpnp() const noexcept
{
    return m_netInfoUpnp;
}

bool HostInfo::NetInfoPmp() const noexcept
{
    return m_netInfoPmp;
}

bool HostInfo::NetInfoPcp() const noexcept
{
    return m_netInfoPcp;
}

const std::string& HostInfo::NetInfoFirewallMode() const noexcept
{
    return m_netInfoFirewallMode;
}

namespace
{

constexpr int ControlCapabilityVersion = 141;

nlohmann::json EncodeHost(const HostInfo& host, int preferredDerp)
{
    nlohmann::json result = {
        {"Hostname", host.Hostname()},
        {"OS", host.OperatingSystem()},
        {"OSVersion", host.OperatingSystemVersion()},
        {"GoArch", host.Architecture()},
        {"IPNVersion", host.ClientVersion()},
    };
    if (!host.FrontendLogId().empty())
    {
        result["FrontendLogID"] = host.FrontendLogId();
    }
    if (!host.BackendLogId().empty())
    {
        result["BackendLogID"] = host.BackendLogId();
    }
    if (preferredDerp > 0)
    {
        result["NetInfo"] = {
            {"MappingVariesByDestIP", host.NetInfoMappingVariesByDestIp()},
            {"WorkingIPv6", host.NetInfoWorkingIpv6()},
            {"OSHasIPv6", host.NetInfoOsHasIpv6()},
            {"WorkingUDP", host.NetInfoWorkingUdp()},
            {"WorkingICMPv4", host.NetInfoWorkingIcmpV4()},
            {"UPnP", host.NetInfoUpnp()},
            {"PMP", host.NetInfoPmp()},
            {"PCP", host.NetInfoPcp()},
            {"PreferredDERP", preferredDerp},
        };
        if (!host.NetInfoFirewallMode().empty())
        {
            result["NetInfo"]["FirewallMode"] = host.NetInfoFirewallMode();
        }
    }
    if (host.WireIngress())
    {
        result["WireIngress"] = true;
    }
    if (host.IngressEnabled())
    {
        result["IngressEnabled"] = true;
    }
    if (!host.Services().empty())
    {
        nlohmann::json services = nlohmann::json::array();
        for (const HostService& service : host.Services())
        {
            services.push_back({
                {"Proto", service.Protocol},
                {"Port", service.Port},
            });
        }
        result["Services"] = std::move(services);
    }
    return result;
}

std::vector<std::uint8_t> Encode(const nlohmann::json& request)
{
    const std::string encoded = request.dump();
    return {encoded.begin(), encoded.end()};
}

nlohmann::json EncodeMapRequest(const std::string& nodeKey,
                                const std::string& discoKey,
                                const HostInfo& host,
                                int preferredDerp,
                                bool stream,
                                bool omitPeers,
                                const std::vector<MapEndpoint>& endpoints,
                                bool keepAlive,
                                bool readOnly)
{
    nlohmann::json request = {
        {"Version", ControlCapabilityVersion},
        {"NodeKey", nodeKey},
        {"DiscoKey", discoKey},
        {"Hostinfo", EncodeHost(host, preferredDerp)},
    };
    if (stream)
    {
        request["Stream"] = true;
    }
    if (omitPeers)
    {
        request["OmitPeers"] = true;
    }
    if (keepAlive)
    {
        request["KeepAlive"] = true;
    }
    if (readOnly)
    {
        request["ReadOnly"] = true;
    }
    if (!endpoints.empty())
    {
        nlohmann::json endpointTexts = nlohmann::json::array();
        nlohmann::json endpointTypes = nlohmann::json::array();
        for (const MapEndpoint& endpoint : endpoints)
        {
            endpointTexts.push_back(endpoint.AddressPort);
            endpointTypes.push_back(static_cast<int>(endpoint.Type));
        }
        request["Endpoints"] = std::move(endpointTexts);
        request["EndpointTypes"] = std::move(endpointTypes);
    }
    return request;
}

} // namespace

std::vector<std::uint8_t> ControlRequest::BuildRegister(const std::string& nodeKey,
                                                        const std::string& authKey,
                                                        const HostInfo& host)
{
    return ControlRequest::BuildRegister(nodeKey, authKey, {}, host);
}

std::vector<std::uint8_t> ControlRequest::BuildRegister(const std::string& nodeKey,
                                                        const std::string& authKey,
                                                        const std::string& followupUrl,
                                                        const HostInfo& host)
{
    nlohmann::json request = {
        {"Version", ControlCapabilityVersion},
        {"NodeKey", nodeKey},
        {"Hostinfo", EncodeHost(host, 0)},
    };
    if (!followupUrl.empty())
    {
        request["Followup"] = followupUrl;
    }
    else if (!authKey.empty())
    {
        request["Auth"] = {{"AuthKey", authKey}};
    }
    return Encode(request);
}

bool IsValidAuthorizationUrl(std::string_view url)
{
    constexpr std::string_view Scheme = "https://";
    const bool containsUnsafeCharacter =
        std::any_of(url.begin(),
                    url.end(),
                    [](char character)
                    {
                        const auto value = static_cast<unsigned char>(character);
                        return value <= 0x20 || value == 0x7f || character == '\\';
                    });
    if (!url.starts_with(Scheme) || containsUnsafeCharacter)
    {
        return false;
    }
    const std::size_t authorityEnd = url.find_first_of("/?#", Scheme.size());
    const std::string_view authority = url.substr(
        Scheme.size(),
        authorityEnd == std::string_view::npos ? authorityEnd : authorityEnd - Scheme.size());
    if (authority.empty() || authority.find('@') != std::string_view::npos)
    {
        return false;
    }
    const std::size_t portSeparator = authority.find(':');
    if (portSeparator != authority.rfind(':'))
    {
        return false;
    }
    const std::string_view host = authority.substr(0, portSeparator);
    if (host.empty() || host.front() == '.' || host.back() == '.' ||
        host.find("..") != std::string_view::npos)
    {
        return false;
    }
    if (portSeparator != std::string_view::npos)
    {
        const std::string_view port = authority.substr(portSeparator + 1);
        if (port.empty() ||
            !std::all_of(port.begin(),
                         port.end(),
                         [](char character)
                         {
                             return std::isdigit(static_cast<unsigned char>(character)) != 0;
                         }))
        {
            return false;
        }
    }
    std::string normalizedHost(host);
    boost::algorithm::to_lower(normalizedHost);
    constexpr std::string_view RootDomain = "tailscale.com";
    if (normalizedHost == RootDomain)
    {
        return true;
    }
    return normalizedHost.size() > RootDomain.size() && normalizedHost.ends_with(RootDomain) &&
           normalizedHost[normalizedHost.size() - RootDomain.size() - 1] == '.';
}

std::string AuthorizationCode(std::string_view url)
{
    constexpr std::string_view Prefix = "https://login.tailscale.com/a/";
    if (!url.starts_with(Prefix))
    {
        return {};
    }
    const std::string_view code = url.substr(Prefix.size());
    if (code.empty() || code.find_first_of("/?#") != std::string_view::npos)
    {
        return {};
    }
    return std::string(code);
}

std::string MachineApprovalUrl(std::string_view address)
{
    constexpr std::string_view MachinesUrl = "https://login.tailscale.com/admin/machines";
    if (address.empty())
    {
        return std::string(MachinesUrl);
    }
    return std::string(MachinesUrl) + '/' + std::string(address);
}

std::optional<RegisterResponse> RegisterResponse::Parse(const std::vector<std::uint8_t>& response)
{
    const nlohmann::json json = nlohmann::json::parse(response, nullptr, false);
    if (!json.is_object())
    {
        return std::nullopt;
    }
    RegisterResponse result;
    result.m_machineAuthorized = json.value("MachineAuthorized", false);
    result.m_nodeKeyExpired = json.value("NodeKeyExpired", false);
    result.m_authUrl = json.value("AuthURL", "");
    result.m_error = json.value("Error", "");
    return result;
}

bool RegisterResponse::MachineAuthorized() const noexcept
{
    return m_machineAuthorized;
}

bool RegisterResponse::NodeKeyExpired() const noexcept
{
    return m_nodeKeyExpired;
}

const std::string& RegisterResponse::AuthUrl() const noexcept
{
    return m_authUrl;
}

const std::string& RegisterResponse::Error() const noexcept
{
    return m_error;
}

bool IsRetryableInitialMapError(int status, std::string_view response)
{
    constexpr int NotFoundStatus = 404;
    return status == NotFoundStatus && response.find("node not found") != std::string_view::npos;
}

std::vector<std::uint8_t> ControlRequest::BuildLogout(const std::string& nodeKey,
                                                      const HostInfo& host)
{
    return Encode({
        {"Version", ControlCapabilityVersion},
        {"NodeKey", nodeKey},
        {"Expiry", "1970-01-01T00:02:03Z"},
        {"Hostinfo", EncodeHost(host, 0)},
    });
}

std::vector<std::uint8_t> ControlRequest::BuildMap(const std::string& nodeKey,
                                                   const std::string& discoKey,
                                                   const HostInfo& host,
                                                   int preferredDerp,
                                                   bool stream,
                                                   bool omitPeers,
                                                   const std::vector<MapEndpoint>& endpoints,
                                                   bool keepAlive)
{
    return Encode(EncodeMapRequest(
        nodeKey, discoKey, host, preferredDerp, stream, omitPeers, endpoints, keepAlive, false));
}

std::vector<std::uint8_t> ControlRequest::BuildReadOnlyMap(const std::string& nodeKey,
                                                           const std::string& discoKey,
                                                           const HostInfo& host)
{
    return Encode(EncodeMapRequest(nodeKey, discoKey, host, 0, false, false, {}, true, true));
}

std::vector<std::uint8_t> ControlRequest::BuildQueryFeature(const std::string& nodeKey,
                                                            const std::string& feature)
{
    return Encode({
        {"Feature", feature},
        {"NodeKey", nodeKey},
    });
}

std::vector<std::uint8_t> ControlRequest::BuildSetDns(const std::string& nodeKey,
                                                      const std::string& name,
                                                      const std::string& value)
{
    return Encode({{"Version", ControlCapabilityVersion},
                   {"NodeKey", nodeKey},
                   {"Name", name},
                   {"Type", "TXT"},
                   {"Value", value}});
}

} // namespace tailgate::control::client
