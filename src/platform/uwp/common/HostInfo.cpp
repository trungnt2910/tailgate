#include "common/HostInfo.h"

#include <cstdint>
#include <format>
#include <string>

#include <winrt/Windows.System.Profile.h>

#include "common/Settings.h"
#include "common/UwpMachineIdentity.h"

namespace tailgate::uwp
{
namespace
{

namespace system_profile = winrt::Windows::System::Profile;

std::string HostVersion()
{
    const std::uint64_t version = std::stoull(
        winrt::to_string(system_profile::AnalyticsInfo::VersionInfo().DeviceFamilyVersion()));
    return std::format("{}.{}.{}.{}",
                       (version >> 48U) & 0xffffU,
                       (version >> 32U) & 0xffffU,
                       (version >> 16U) & 0xffffU,
                       version & 0xffffU);
}

} // namespace

tailgate::control::client::HostInfo BuildHostInfo()
{
    std::string hostname = CollectComputerHostname();
    const std::string hostnameOverride = winrt::to_string(Settings::GetString(L"Hostname"));
    if (!hostnameOverride.empty())
    {
        hostname = hostnameOverride;
    }

    tailgate::control::client::HostInfo host;
    host.Hostname = hostname;
    host.OperatingSystem = "UWP";
    host.OperatingSystemVersion = HostVersion();
    // Official Tailscale architecture names (GOARCH).
#if defined(_M_ARM64) || defined(__aarch64__)
    host.Architecture = "arm64";
#elif defined(_M_X64) || defined(__x86_64__)
    host.Architecture = "amd64";
#elif defined(_M_ARM) || defined(__arm__)
    host.Architecture = "arm";
#elif defined(_M_IX86) || defined(__i386__)
    host.Architecture = "386";
#else
    host.Architecture = "unknown";
#endif
    return host;
}

} // namespace tailgate::uwp
