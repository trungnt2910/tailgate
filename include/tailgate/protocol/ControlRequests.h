#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tailgate::protocol
{

struct HostInfo
{
    std::string Hostname;
    std::string OperatingSystem;
    std::string OperatingSystemVersion;
    std::string Architecture;
    std::string ClientVersion = "Tailgate";
};

[[nodiscard]] std::vector<std::uint8_t>
BuildRegisterRequest(const std::string& nodeKey, const std::string& authKey, const HostInfo& host);

[[nodiscard]] std::vector<std::uint8_t> BuildMapRequest(const std::string& nodeKey,
                                                        const std::string& discoKey,
                                                        const HostInfo& host,
                                                        int preferredDerp = 0,
                                                        bool stream = false);

[[nodiscard]] std::vector<std::uint8_t> BuildLogoutRequest(const std::string& nodeKey,
                                                           const HostInfo& host);

} // namespace tailgate::protocol
