#include "VpnReconnectState.h"

namespace tailgate::uwp
{

bool VpnReconnectState::RetryActivation(
    bool legacyWindows,
    winrt::Windows::Networking::Vpn::VpnManagementErrorStatus result,
    std::optional<winrt::Windows::Networking::Vpn::VpnManagementConnectionStatus> status,
    std::chrono::steady_clock::duration elapsed,
    std::size_t retries) noexcept
{
    constexpr auto ActivationTimeout = std::chrono::seconds(15);
    constexpr std::size_t MaximumRetries = 2;
    return legacyWindows &&
           result == winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::Other &&
           DisconnectComplete(status) && elapsed >= ActivationTimeout && retries < MaximumRetries;
}

bool VpnReconnectState::DisconnectComplete(
    std::optional<winrt::Windows::Networking::Vpn::VpnManagementConnectionStatus> status) noexcept
{
    // RS2 invalidates the RAS handle when the connection ends. Waiting for an explicit
    // Disconnected state in that case prevents redial until the deadline expires.
    return !status ||
           *status == winrt::Windows::Networking::Vpn::VpnManagementConnectionStatus::Disconnected;
}

bool VpnReconnectState::RetryWithFreshAgent(
    winrt::Windows::Networking::Vpn::VpnManagementErrorStatus result,
    std::optional<winrt::Windows::Networking::Vpn::VpnManagementConnectionStatus> status) noexcept
{
    return result == winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::AlreadyConnected &&
           DisconnectComplete(status);
}

bool VpnReconnectState::NeedsProfileReplacement(
    bool afterDisconnect,
    winrt::Windows::Networking::Vpn::VpnManagementErrorStatus result,
    std::optional<winrt::Windows::Networking::Vpn::VpnManagementConnectionStatus> status) noexcept
{
    return afterDisconnect &&
           result == winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::Other && !status;
}

} // namespace tailgate::uwp
