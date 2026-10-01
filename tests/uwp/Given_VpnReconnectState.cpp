#include <chrono>
#include <optional>

#include <gtest/gtest.h>

#include "common/VpnReconnectState.h"

namespace
{

using Status = winrt::Windows::Networking::Vpn::VpnManagementConnectionStatus;
using tailgate::uwp::VpnReconnectState;

TEST(Given_VpnReconnectState, When_ConnectionHandleRetires_Then_AllowsRedial)
{
    const std::optional<Status> status = std::nullopt;

    const auto complete = VpnReconnectState::DisconnectComplete(status);

    EXPECT_TRUE(complete);
}

TEST(Given_VpnReconnectState, When_ProfileReportsDisconnected_Then_AllowsRedial)
{
    const std::optional<Status> status = Status::Disconnected;

    const auto complete = VpnReconnectState::DisconnectComplete(status);

    EXPECT_TRUE(complete);
}

TEST(Given_VpnReconnectState, When_ProfileRemainsConnected_Then_KeepsWaiting)
{
    const std::optional<Status> status = Status::Connected;

    const auto complete = VpnReconnectState::DisconnectComplete(status);

    EXPECT_FALSE(complete);
}

TEST(Given_VpnReconnectState, When_ProfileIsStillDisconnecting_Then_KeepsWaiting)
{
    const std::optional<Status> status = Status::Disconnecting;

    const auto complete = VpnReconnectState::DisconnectComplete(status);

    EXPECT_FALSE(complete);
}

TEST(Given_VpnReconnectState, When_ProfileIsStillConnecting_Then_KeepsWaiting)
{
    const std::optional<Status> status = Status::Connecting;

    const auto complete = VpnReconnectState::DisconnectComplete(status);

    EXPECT_FALSE(complete);
}

TEST(Given_VpnReconnectState, When_RedialSaysConnectedWithRetiredHandle_Then_RefreshesAgent)
{
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::AlreadyConnected;

    const auto retry = VpnReconnectState::RetryWithFreshAgent(result, std::nullopt);

    EXPECT_TRUE(retry);
}

TEST(Given_VpnReconnectState, When_RedialSaysConnectedWithDisconnectedProfile_Then_RefreshesAgent)
{
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::AlreadyConnected;

    const auto retry = VpnReconnectState::RetryWithFreshAgent(result, Status::Disconnected);

    EXPECT_TRUE(retry);
}

TEST(Given_VpnReconnectState, When_RedialConfirmsExistingConnection_Then_KeepsAgent)
{
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::AlreadyConnected;

    const auto retry = VpnReconnectState::RetryWithFreshAgent(result, Status::Connected);

    EXPECT_FALSE(retry);
}

TEST(Given_VpnReconnectState, When_RedialFails_Then_DoesNotRetryWithFreshAgent)
{
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::ServerConnection;

    const auto retry = VpnReconnectState::RetryWithFreshAgent(result, std::nullopt);

    EXPECT_FALSE(retry);
}

TEST(Given_VpnReconnectState, When_RedialFailsWithInvalidHandle_Then_ReplacesProfile)
{
    const bool afterDisconnect = true;
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::Other;
    const std::optional<Status> connection = std::nullopt;

    const auto replace =
        VpnReconnectState::NeedsProfileReplacement(afterDisconnect, result, connection);

    EXPECT_TRUE(replace);
}

TEST(Given_VpnReconnectState,
     When_InitialConnectFailsWithInvalidHandle_Then_PreservesAuthorizationRetry)
{
    const bool afterDisconnect = false;
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::Other;
    const std::optional<Status> connection = std::nullopt;

    const auto replace =
        VpnReconnectState::NeedsProfileReplacement(afterDisconnect, result, connection);

    EXPECT_FALSE(replace);
}

TEST(Given_VpnReconnectState, When_RedialFailsWithValidDisconnectedProfile_Then_KeepsProfile)
{
    const bool afterDisconnect = true;
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::Other;
    const std::optional<Status> connection = Status::Disconnected;

    const auto replace =
        VpnReconnectState::NeedsProfileReplacement(afterDisconnect, result, connection);

    EXPECT_FALSE(replace);
}

TEST(Given_VpnReconnectState, When_RedialFailsWithConnectedProfile_Then_KeepsProfile)
{
    const bool afterDisconnect = true;
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::Other;
    const std::optional<Status> connection = Status::Connected;

    const auto replace =
        VpnReconnectState::NeedsProfileReplacement(afterDisconnect, result, connection);

    EXPECT_FALSE(replace);
}

TEST(Given_VpnReconnectState,
     When_RedialReportsStaleExistingConnection_Then_KeepsAgentRefreshRecovery)
{
    const bool afterDisconnect = true;
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::AlreadyConnected;
    const std::optional<Status> connection = std::nullopt;

    const auto replace =
        VpnReconnectState::NeedsProfileReplacement(afterDisconnect, result, connection);

    EXPECT_FALSE(replace);
}

TEST(Given_VpnReconnectState, When_RedialIsDenied_Then_KeepsProfile)
{
    const bool afterDisconnect = true;
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::AccessDenied;
    const std::optional<Status> connection = std::nullopt;

    const auto replace =
        VpnReconnectState::NeedsProfileReplacement(afterDisconnect, result, connection);

    EXPECT_FALSE(replace);
}

TEST(Given_VpnReconnectState, When_RedialCannotReachServer_Then_KeepsProfile)
{
    const bool afterDisconnect = true;
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::ServerConnection;
    const std::optional<Status> connection = std::nullopt;

    const auto replace =
        VpnReconnectState::NeedsProfileReplacement(afterDisconnect, result, connection);

    EXPECT_FALSE(replace);
}

TEST(Given_VpnReconnectState,
     When_Rs2ActivationTimesOutWithRetiredHandle_Then_RetriesWithoutReplacingProfile)
{
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::Other;

    const auto retry =
        VpnReconnectState::RetryActivation(true, result, std::nullopt, std::chrono::seconds(15), 0);

    EXPECT_TRUE(retry);
}

TEST(Given_VpnReconnectState,
     When_Rs2ActivationTimesOutWhileDisconnected_Then_RetriesWithoutReplacingProfile)
{
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::Other;

    const auto retry = VpnReconnectState::RetryActivation(
        true, result, Status::Disconnected, std::chrono::seconds(16), 1);

    EXPECT_TRUE(retry);
}

TEST(Given_VpnReconnectState, When_NewerWindowsReturnsSameError_Then_DoesNotRetry)
{
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::Other;

    const auto retry = VpnReconnectState::RetryActivation(
        false, result, std::nullopt, std::chrono::seconds(15), 0);

    EXPECT_FALSE(retry);
}

TEST(Given_VpnReconnectState, When_Rs2ProfileFailsImmediately_Then_DoesNotRetry)
{
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::Other;

    const auto retry =
        VpnReconnectState::RetryActivation(true, result, std::nullopt, std::chrono::seconds(2), 0);

    EXPECT_FALSE(retry);
}

TEST(Given_VpnReconnectState, When_Rs2ActivationRetriesAreExhausted_Then_ReturnsFailure)
{
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::Other;

    const auto retry =
        VpnReconnectState::RetryActivation(true, result, std::nullopt, std::chrono::seconds(15), 2);

    EXPECT_FALSE(retry);
}

TEST(Given_VpnReconnectState, When_Rs2ConnectionIsStillStarting_Then_DoesNotStartOverlappingDial)
{
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::Other;

    const auto retry = VpnReconnectState::RetryActivation(
        true, result, Status::Connecting, std::chrono::seconds(15), 0);

    EXPECT_FALSE(retry);
}

TEST(Given_VpnReconnectState, When_Rs2ConnectionIsStillStopping_Then_DoesNotStartOverlappingDial)
{
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::Other;

    const auto retry = VpnReconnectState::RetryActivation(
        true, result, Status::Disconnecting, std::chrono::seconds(15), 0);

    EXPECT_FALSE(retry);
}

TEST(Given_VpnReconnectState, When_Rs2ProfileIsConnected_Then_DoesNotRedial)
{
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::Other;

    const auto retry = VpnReconnectState::RetryActivation(
        true, result, Status::Connected, std::chrono::seconds(15), 0);

    EXPECT_FALSE(retry);
}

TEST(Given_VpnReconnectState, When_Rs2AuthenticationFails_Then_DoesNotRetry)
{
    const auto result =
        winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::GeneralAuthenticationFailure;

    const auto retry =
        VpnReconnectState::RetryActivation(true, result, std::nullopt, std::chrono::seconds(15), 0);

    EXPECT_FALSE(retry);
}

TEST(Given_VpnReconnectState, When_Rs2AccessIsDenied_Then_DoesNotRetry)
{
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::AccessDenied;

    const auto retry =
        VpnReconnectState::RetryActivation(true, result, std::nullopt, std::chrono::seconds(15), 0);

    EXPECT_FALSE(retry);
}

TEST(Given_VpnReconnectState, When_Rs2ServerIsUnreachable_Then_DoesNotRetry)
{
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::ServerConnection;

    const auto retry =
        VpnReconnectState::RetryActivation(true, result, std::nullopt, std::chrono::seconds(15), 0);

    EXPECT_FALSE(retry);
}

TEST(Given_VpnReconnectState, When_Rs2ProfileIsMissing_Then_DoesNotRetry)
{
    const auto result =
        winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::CannotFindProfile;

    const auto retry =
        VpnReconnectState::RetryActivation(true, result, std::nullopt, std::chrono::seconds(15), 0);

    EXPECT_FALSE(retry);
}

TEST(Given_VpnReconnectState, When_Rs2ConnectSucceeds_Then_DoesNotRetry)
{
    const auto result = winrt::Windows::Networking::Vpn::VpnManagementErrorStatus::Ok;

    const auto retry = VpnReconnectState::RetryActivation(
        true, result, Status::Connected, std::chrono::seconds(15), 0);

    EXPECT_FALSE(retry);
}

} // namespace
