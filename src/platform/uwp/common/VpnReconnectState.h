#pragma once

#include <chrono>
#include <cstddef>
#include <optional>

#include <winrt/Windows.Networking.Vpn.h>

namespace tailgate::uwp
{

class VpnReconnectState final
{
public:
    // RS2 can time out activating the provider before its Connect callback runs.
    // Reuse the profile for at most two more dials; do not generalize Other into
    // a transient error on newer systems or retry an immediate profile failure.
    [[nodiscard]] static bool RetryActivation(
        bool legacyWindows,
        winrt::Windows::Networking::Vpn::VpnManagementErrorStatus result,
        std::optional<winrt::Windows::Networking::Vpn::VpnManagementConnectionStatus> status,
        std::chrono::steady_clock::duration elapsed,
        std::size_t retries) noexcept;
    // Only after DisconnectProfileAsync has accepted the disconnect request.
    // An absent status represents E_HANDLE from an enumerated installed profile.
    [[nodiscard]] static bool
    DisconnectComplete(std::optional<winrt::Windows::Networking::Vpn::VpnManagementConnectionStatus>
                           status) noexcept;
    // After an accepted disconnect, a cached agent may return AlreadyConnected
    // while the profile still identifies the retired connection.
    [[nodiscard]] static bool RetryWithFreshAgent(
        winrt::Windows::Networking::Vpn::VpnManagementErrorStatus result,
        std::optional<winrt::Windows::Networking::Vpn::VpnManagementConnectionStatus>
            status) noexcept;
    // RS2 can reject the retired profile with Other. Only repair it during redial,
    // when E_HANDLE confirms that the profile's connection handle is invalid.
    [[nodiscard]] static bool NeedsProfileReplacement(
        bool afterDisconnect,
        winrt::Windows::Networking::Vpn::VpnManagementErrorStatus result,
        std::optional<winrt::Windows::Networking::Vpn::VpnManagementConnectionStatus>
            status) noexcept;
};

} // namespace tailgate::uwp
