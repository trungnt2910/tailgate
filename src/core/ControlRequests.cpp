#include "tailgate/protocol/ControlRequests.h"

#include <nlohmann/json.hpp>

namespace tailgate::protocol
{
namespace
{

nlohmann::json EncodeHost(const HostInfo& host, int preferredDerp)
{
    return {
        {"Hostname", host.Hostname},
        {"OS", host.OperatingSystem},
        {"OSVersion", host.OperatingSystemVersion},
        {"GoArch", host.Architecture},
        {"IPNVersion", host.ClientVersion},
        {"NetInfo", {{"PreferredDERP", preferredDerp}}},
    };
}

std::vector<std::uint8_t> Encode(const nlohmann::json& request)
{
    const std::string encoded = request.dump();
    return {encoded.begin(), encoded.end()};
}

} // namespace

std::vector<std::uint8_t>
BuildRegisterRequest(const std::string& nodeKey, const std::string& authKey, const HostInfo& host)
{
    return Encode({
        {"Version", 141},
        {"NodeKey", nodeKey},
        {"Auth", {{"AuthKey", authKey}}},
        {"Hostinfo", EncodeHost(host, 0)},
        {"Ephemeral", true},
    });
}

std::vector<std::uint8_t> BuildLogoutRequest(const std::string& nodeKey, const HostInfo& host)
{
    return Encode({
        {"Version", 141},
        {"NodeKey", nodeKey},
        {"Expiry", "1970-01-01T00:02:03Z"},
        {"Hostinfo", EncodeHost(host, 0)},
    });
}

std::vector<std::uint8_t> BuildMapRequest(const std::string& nodeKey,
                                          const std::string& discoKey,
                                          const HostInfo& host,
                                          int preferredDerp,
                                          bool stream)
{
    return Encode({
        {"Version", 141},
        {"NodeKey", nodeKey},
        {"DiscoKey", discoKey},
        {"Stream", stream},
        {"KeepAlive", true},
        {"Compress", ""},
        {"Hostinfo", EncodeHost(host, preferredDerp)},
    });
}

} // namespace tailgate::protocol
