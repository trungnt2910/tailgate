#pragma once

#include <cstdint>
#include <optional>

#include <tailgate/Logger.h>

#include "common/UwpFormat.h"

#include "app/controller/SessionController.h"
#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

class AuthorizationController;
class ControlPlaneController;
class InteractiveAuthorizationController;
class InteractiveAuthorizationState;
class SettingsController;
class TailgateRelayController;
class VpnProfileController;

struct ActiveConnectContext
{
    std::optional<winrt::hstring> TailgateServer;
    std::optional<std::uint64_t> RelayOperationId;
    winrt::hstring AuthKey;
    winrt::hstring AttemptHostname;
    bool ShowDialogOnFailure = false;
    bool RestartConnectedProfile = false;
    bool HadStoredProfile = false;
    bool RestoringPreviousConnection = false;
    bool WaitingForAuthorizationListener = false;
    std::optional<ConnectionSettingsSnapshot> RollbackSettings;
    std::optional<UwpError::Code> Failure;
};

class SessionControllerImpl final : public SessionController
{
public:
    SessionControllerImpl(AuthorizationController& authorizationController,
                          ControlPlaneController& controlPlaneController,
                          InteractiveAuthorizationController& interactiveAuthorizationController,
                          SettingsController& settingsController,
                          TailgateRelayController& tailgateRelayController,
                          VpnProfileController& vpnProfileController);

    [[nodiscard]] const SessionState& GetState() const noexcept override;
    void Connect(winrt::hstring tailgateServer,
                 winrt::hstring authKey,
                 bool showDialogOnFailure,
                 bool restartConnectedProfile,
                 std::optional<ConnectionSettingsSnapshot> rollbackSettings) override;
    void ConnectStoredOrRequestSignIn() override;
    void Disconnect() override;
    void Logout() override;
    void Refresh() override;
    void CancelActiveConnectionAttempt() override;
    void BeginExitNodeChange() override;
    void FinishExitNodeChange(std::optional<UwpError::Code> error) override;

private:
    [[nodiscard]] bool OperationInProgress(const char* operation) const;
    [[nodiscard]] bool ShowCachedAuthorization(const winrt::hstring& tailgateServer,
                                               const winrt::hstring& authKey);
    void StartConnect(winrt::hstring tailgateServer,
                      winrt::hstring authKey,
                      bool showDialogOnFailure,
                      bool restartConnectedProfile,
                      std::optional<ConnectionSettingsSnapshot> rollbackSettings);
    void StartTailgateRelayPreflight(const winrt::hstring& tailgateServer);
    void StartVpnConnect();
    void HandleConnectFailure(std::optional<UwpError::Code> error);
    void FinishConnectWorkflow();
    void StartPendingConnect();
    void HandleInteractiveAuthorization(const InteractiveAuthorizationState& interactive);
    void OnVpnProfileChanged();
    void OnControlPlaneChanged();
    void OnInteractiveAuthorizationChanged();
    void OnTailgateRelayChanged();

    AuthorizationController& m_authorizationController;
    ControlPlaneController& m_controlPlaneController;
    InteractiveAuthorizationController& m_interactiveAuthorizationController;
    SettingsController& m_settingsController;
    TailgateRelayController& m_tailgateRelayController;
    VpnProfileController& m_vpnProfileController;
    std::optional<ActiveConnectContext> m_activeConnect;
    std::uint64_t m_nextTailgateRelayOperationId = 0;
    bool m_logoutWaitingForControlPlane = false;
    SessionState m_state;
    StateEventRegistration m_controlPlaneRegistration;
    StateEventRegistration m_interactiveAuthorizationRegistration;
    StateEventRegistration m_tailgateRelayRegistration;
    StateEventRegistration m_vpnProfileRegistration;
    Logger m_logger{"uwp-session-ctrl"};
};

} // namespace tailgate::uwp
