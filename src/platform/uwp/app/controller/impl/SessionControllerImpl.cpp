#include "app/controller/impl/SessionControllerImpl.h"

#include <exception>
#include <optional>
#include <utility>

#include "app/controller/AuthorizationController.h"
#include "app/controller/ControlPlaneController.h"
#include "app/controller/InteractiveAuthorizationController.h"
#include "app/controller/SettingsController.h"
#include "app/controller/TailgateRelayController.h"
#include "app/controller/VpnProfileController.h"

namespace tailgate::uwp
{

SessionControllerImpl::SessionControllerImpl(
    AuthorizationController& authorizationController,
    ControlPlaneController& controlPlaneController,
    InteractiveAuthorizationController& interactiveAuthorizationController,
    SettingsController& settingsController,
    TailgateRelayController& tailgateRelayController,
    VpnProfileController& vpnProfileController)
    : m_authorizationController(authorizationController),
      m_controlPlaneController(controlPlaneController),
      m_interactiveAuthorizationController(interactiveAuthorizationController),
      m_settingsController(settingsController),
      m_tailgateRelayController(tailgateRelayController),
      m_vpnProfileController(vpnProfileController)
{
    m_controlPlaneRegistration = m_controlPlaneController.GetState().Subscribe(
        [this](const auto&, const auto&)
        {
            OnControlPlaneChanged();
        });
    m_interactiveAuthorizationRegistration =
        m_interactiveAuthorizationController.GetState().Subscribe(
            [this](const auto&, const auto&)
            {
                OnInteractiveAuthorizationChanged();
            });
    m_tailgateRelayRegistration = m_tailgateRelayController.GetState().Subscribe(
        [this](const auto&, const auto&)
        {
            OnTailgateRelayChanged();
        });
    m_vpnProfileRegistration = m_vpnProfileController.GetState().Subscribe(
        [this](const auto&, const auto&)
        {
            OnVpnProfileChanged();
        });
}

const SessionState& SessionControllerImpl::GetState() const noexcept
{
    return m_state;
}

bool SessionControllerImpl::OperationInProgress(const char* operation) const
{
    if (!m_state.ConnectionOperationActive())
    {
        return false;
    }
    m_logger.LogDebug("ignoring {}: a connection operation is already in progress", operation);
    return true;
}

bool SessionControllerImpl::ShowCachedAuthorization(const winrt::hstring& tailgateServer,
                                                    const winrt::hstring& authKey)
{
    m_settingsController.Reload();
    m_authorizationController.FindCached(
        tailgateServer, authKey, m_settingsController.GetState().Hostname());
    const auto& authorization = m_authorizationController.GetState().MatchedAuthorization();
    if (!authorization)
    {
        return false;
    }
    m_authorizationController.RequestPrompt(authorization->Url, authorization->MachineApproval);
    return true;
}

void SessionControllerImpl::Connect(winrt::hstring tailgateServer,
                                    winrt::hstring authKey,
                                    bool showDialogOnFailure,
                                    bool restartConnectedProfile,
                                    std::optional<ConnectionSettingsSnapshot> rollbackSettings)
{
    if (m_state.ConnectionOperationActive())
    {
        bool cachedAuthorizationShown = false;
        if (m_activeConnect && m_activeConnect->TailgateServer)
        {
            const TailgateRelayState& relay = m_tailgateRelayController.GetState();
            const bool sameServer =
                tailgateServer == *m_activeConnect->TailgateServer ||
                (!relay.Error() && relay.TailgateServer() == *m_activeConnect->TailgateServer &&
                 relay.RequestedTailgateServer() == tailgateServer);
            if (sameServer)
            {
                cachedAuthorizationShown =
                    ShowCachedAuthorization(*m_activeConnect->TailgateServer, authKey);
            }
        }
        if (cachedAuthorizationShown)
        {
            m_state.PendingConnect(std::nullopt);
            return;
        }
        PendingConnectRequest request;
        request.TailgateServer = std::move(tailgateServer);
        request.AuthKey = std::move(authKey);
        request.ShowDialogOnFailure = showDialogOnFailure;
        request.RestartConnectedProfile = restartConnectedProfile;
        request.RollbackSettings = std::move(rollbackSettings);
        m_state.Update(
            [&](SessionState& state)
            {
                state.PendingConnect(std::move(request));
                state.Activity(SessionActivity::Starting);
                state.Busy(true);
            });
        return;
    }

    m_state.Update(
        [](SessionState& state)
        {
            state.ConnectionOperationActive(true);
            state.Activity(SessionActivity::Starting);
            state.Busy(true);
            state.Error(std::nullopt);
        });
    StartConnect(std::move(tailgateServer),
                 std::move(authKey),
                 showDialogOnFailure,
                 restartConnectedProfile,
                 std::move(rollbackSettings));
}

void SessionControllerImpl::StartConnect(winrt::hstring tailgateServer,
                                         winrt::hstring authKey,
                                         bool showDialogOnFailure,
                                         bool restartConnectedProfile,
                                         std::optional<ConnectionSettingsSnapshot> rollbackSettings)
{
    m_settingsController.Reload();
    ActiveConnectContext context;
    context.AuthKey = std::move(authKey);
    context.AttemptHostname = m_settingsController.GetState().Hostname();
    context.ShowDialogOnFailure = showDialogOnFailure;
    context.RestartConnectedProfile = restartConnectedProfile;
    context.HadStoredProfile = m_settingsController.GetState().HasStoredProfile();
    context.RollbackSettings = std::move(rollbackSettings);
    m_activeConnect = std::move(context);

    const bool requiresPreflight =
        !m_settingsController.GetState().ProfileValidated() ||
        m_settingsController.GetState().TailgateServer() != tailgateServer;
    if (requiresPreflight)
    {
        m_logger.LogInfo("validating Tailgate server");
        StartTailgateRelayPreflight(tailgateServer);
        return;
    }
    m_activeConnect->TailgateServer = std::move(tailgateServer);
    (void)ShowCachedAuthorization(*m_activeConnect->TailgateServer, m_activeConnect->AuthKey);
    m_settingsController.SetAuthentication(*m_activeConnect->TailgateServer,
                                           m_activeConnect->AuthKey);
    StartVpnConnect();
}

void SessionControllerImpl::StartTailgateRelayPreflight(const winrt::hstring& tailgateServer)
{
    if (!m_activeConnect)
    {
        return;
    }
    const std::uint64_t operationId = ++m_nextTailgateRelayOperationId;
    m_activeConnect->RelayOperationId = operationId;
    m_tailgateRelayController.Preflight(operationId, tailgateServer);
}

void SessionControllerImpl::StartVpnConnect()
{
    if (!m_activeConnect || !m_activeConnect->TailgateServer)
    {
        return;
    }
    m_activeConnect->WaitingForAuthorizationListener = true;
    m_interactiveAuthorizationController.Listen(*m_activeConnect->TailgateServer);
}

void SessionControllerImpl::OnTailgateRelayChanged()
{
    const TailgateRelayState& relay = m_tailgateRelayController.GetState();
    if (relay.Busy() || !m_activeConnect || !m_activeConnect->RelayOperationId ||
        relay.OperationId() != *m_activeConnect->RelayOperationId)
    {
        return;
    }
    m_activeConnect->RelayOperationId.reset();
    if (relay.Error())
    {
        HandleConnectFailure(relay.Error());
        return;
    }
    m_activeConnect->TailgateServer = relay.TailgateServer();
    (void)ShowCachedAuthorization(*m_activeConnect->TailgateServer, m_activeConnect->AuthKey);
    m_settingsController.SetAuthentication(*m_activeConnect->TailgateServer,
                                           m_activeConnect->AuthKey);
    StartVpnConnect();
}

void SessionControllerImpl::OnInteractiveAuthorizationChanged()
{
    const InteractiveAuthorizationState& interactive =
        m_interactiveAuthorizationController.GetState();
    if (!m_activeConnect || !m_activeConnect->TailgateServer ||
        interactive.TailgateServer() != *m_activeConnect->TailgateServer)
    {
        return;
    }
    HandleInteractiveAuthorization(interactive);
}

void SessionControllerImpl::HandleInteractiveAuthorization(
    const InteractiveAuthorizationState& interactive)
{
    if (m_activeConnect->Failure == UwpError::Code::ConnectionCancelled &&
        interactive.Status() != InteractiveAuthorizationStatus::Cancelled &&
        interactive.Status() != InteractiveAuthorizationStatus::Idle)
    {
        return;
    }
    switch (interactive.Status())
    {
    case InteractiveAuthorizationStatus::Listening:
        if (m_activeConnect->WaitingForAuthorizationListener)
        {
            m_activeConnect->WaitingForAuthorizationListener = false;
            m_vpnProfileController.Connect(*m_activeConnect->TailgateServer,
                                           m_activeConnect->AuthKey,
                                           m_activeConnect->RestartConnectedProfile);
        }
        return;
    case InteractiveAuthorizationStatus::LoginRequired:
    case InteractiveAuthorizationStatus::MachineApprovalRequired:
    {
        AuthorizationCache cache;
        cache.Url = interactive.Url();
        cache.TailgateServer = interactive.TailgateServer();
        cache.AuthKey = m_activeConnect->AuthKey;
        cache.Hostname = m_activeConnect->AttemptHostname;
        const bool machineApproval =
            interactive.Status() == InteractiveAuthorizationStatus::MachineApprovalRequired;
        cache.MachineApproval = machineApproval;
        m_authorizationController.Cache(std::move(cache));
        m_authorizationController.RequestPrompt(interactive.Url(), machineApproval);
        m_state.Error(machineApproval ? UwpError::Code::DeviceApprovalRequired
                                      : UwpError::Code::DeviceAuthorizationRequired);
        return;
    }
    case InteractiveAuthorizationStatus::Authorized:
        m_authorizationController.Clear();
        return;
    case InteractiveAuthorizationStatus::Failed:
        m_authorizationController.Clear();
        m_activeConnect->Failure = interactive.Error().value_or(UwpError::Code::Unexpected);
        if (m_vpnProfileController.GetState().Busy())
        {
            m_vpnProfileController.CancelConnect();
        }
        else
        {
            HandleConnectFailure(m_activeConnect->Failure);
        }
        return;
    case InteractiveAuthorizationStatus::Cancelled:
        m_activeConnect->Failure = UwpError::Code::ConnectionCancelled;
        m_vpnProfileController.CancelConnect();
        return;
    case InteractiveAuthorizationStatus::Idle:
        return;
    }
}

void SessionControllerImpl::OnVpnProfileChanged()
{
    const VpnProfileState& vpn = m_vpnProfileController.GetState();
    if (vpn.Busy())
    {
        return;
    }

    switch (vpn.Activity())
    {
    case VpnProfileActivity::Connecting:
        if (!m_activeConnect)
        {
            return;
        }
        m_interactiveAuthorizationController.Stop();
        if (vpn.Connected() && !vpn.Error())
        {
            m_state.Update(
                [](SessionState& state)
                {
                    state.Connected(true);
                    state.Error(std::nullopt);
                });
            FinishConnectWorkflow();
            return;
        }
        HandleConnectFailure(m_activeConnect->Failure ? m_activeConnect->Failure : vpn.Error());
        return;
    case VpnProfileActivity::Disconnecting:
        m_state.Update(
            [&](SessionState& state)
            {
                if (!vpn.Error())
                {
                    state.Connected(false);
                }
                state.Error(vpn.Error());
                state.ConnectionOperationActive(false);
                state.Busy(false);
                state.Activity(SessionActivity::Idle);
            });
        return;
    case VpnProfileActivity::LoggingOut:
        if (vpn.Error())
        {
            m_state.Update(
                [&](SessionState& state)
                {
                    state.Error(vpn.Error());
                    state.ConnectionOperationActive(false);
                    state.Busy(false);
                    state.Activity(SessionActivity::Idle);
                });
            return;
        }
        m_logoutWaitingForControlPlane = true;
        m_controlPlaneController.Logout(m_settingsController.GetState().MachinePrivateKey(),
                                        m_settingsController.GetState().NodePrivateKey());
        return;
    case VpnProfileActivity::Discarding:
        if (vpn.Error())
        {
            m_logger.LogWarning("failed to discard incomplete VPN profile");
            FinishConnectWorkflow();
            return;
        }
        m_controlPlaneController.Logout(m_settingsController.GetState().MachinePrivateKey(),
                                        m_settingsController.GetState().NodePrivateKey());
        return;
    case VpnProfileActivity::Refreshing:
        m_state.Update(
            [&](SessionState& state)
            {
                state.Connected(!vpn.Error() && vpn.Connected());
                state.Busy(false);
                state.Activity(SessionActivity::Idle);
            });
        return;
    case VpnProfileActivity::Idle:
        return;
    }
}

void SessionControllerImpl::HandleConnectFailure(std::optional<UwpError::Code> error)
{
    if (!m_activeConnect)
    {
        return;
    }
    m_activeConnect->Failure = error.value_or(UwpError::Code::VpnProfileDidNotConnect);
    if (!m_activeConnect->RestoringPreviousConnection && m_activeConnect->RollbackSettings)
    {
        const ConnectionSettingsSnapshot previous = *m_activeConnect->RollbackSettings;
        m_settingsController.RestoreConnectionSettings(previous);
        m_activeConnect->RestoringPreviousConnection = true;
        m_activeConnect->AuthKey.clear();
        m_activeConnect->RestartConnectedProfile = false;
        m_activeConnect->RollbackSettings.reset();
        m_activeConnect->TailgateServer.reset();
        const std::optional<winrt::hstring>& previousTailgateServer = previous.TailgateServer;
        if (previousTailgateServer && !previousTailgateServer->empty())
        {
            m_activeConnect->Failure.reset();
            StartTailgateRelayPreflight(*previousTailgateServer);
            return;
        }
        m_logger.LogWarning("cannot restore previous VPN server: server is missing");
        m_activeConnect->Failure = UwpError::Code::PreviousConnectionRestoreFailed;
    }
    if (m_activeConnect->RestoringPreviousConnection)
    {
        m_activeConnect->Failure = UwpError::Code::PreviousConnectionRestoreFailed;
    }

    m_state.Update(
        [&](SessionState& state)
        {
            state.Connected(false);
            state.Error(m_activeConnect->Failure);
        });
    m_settingsController.Reload();
    const bool requiresCleanup = !m_activeConnect->HadStoredProfile &&
                                 !m_settingsController.GetState().RegistrationComplete();
    if (requiresCleanup)
    {
        m_vpnProfileController.DiscardProfile();
        return;
    }
    FinishConnectWorkflow();
}

void SessionControllerImpl::OnControlPlaneChanged()
{
    const ControlPlaneState& control = m_controlPlaneController.GetState();
    if (control.Busy())
    {
        return;
    }
    if (control.Error())
    {
        m_logger.LogWarning("node key expiry deferred to control cleanup");
    }
    m_settingsController.Clear();
    if (m_activeConnect)
    {
        FinishConnectWorkflow();
        return;
    }
    if (!m_logoutWaitingForControlPlane)
    {
        return;
    }
    m_logoutWaitingForControlPlane = false;
    m_state.Update(
        [](SessionState& state)
        {
            state.Error(std::nullopt);
            state.Connected(false);
            state.Busy(false);
            state.ConnectionOperationActive(false);
            state.Activity(SessionActivity::Idle);
        });
}

void SessionControllerImpl::FinishConnectWorkflow()
{
    if (!m_activeConnect)
    {
        return;
    }
    const bool requestSignIn = !m_state.Connected() && m_activeConnect->ShowDialogOnFailure;
    m_activeConnect.reset();
    if (!m_state.Connected())
    {
        m_authorizationController.Clear();
    }
    m_state.Update(
        [&](SessionState& state)
        {
            state.ConnectionOperationActive(false);
            state.Busy(false);
            state.Activity(SessionActivity::Idle);
            if (requestSignIn)
            {
                state.SignInRequest(state.SignInRequest() + 1);
            }
        });
    if (m_state.Connected())
    {
        m_authorizationController.Clear();
        m_authorizationController.ClearPendingAuthentication();
    }
    StartPendingConnect();
}

void SessionControllerImpl::StartPendingConnect()
{
    if (!m_state.PendingConnect())
    {
        return;
    }
    auto pending = *m_state.PendingConnect();
    m_state.PendingConnect(std::nullopt);
    Connect(std::move(pending.TailgateServer),
            std::move(pending.AuthKey),
            pending.ShowDialogOnFailure,
            pending.RestartConnectedProfile || m_state.Connected(),
            std::move(pending.RollbackSettings));
}

void SessionControllerImpl::ConnectStoredOrRequestSignIn()
{
    m_settingsController.Reload();
    if (m_settingsController.GetState().HasStoredProfile())
    {
        Connect(m_settingsController.GetState().TailgateServer(), L"", false, false, std::nullopt);
        return;
    }
    m_state.SignInRequest(m_state.SignInRequest() + 1);
}

void SessionControllerImpl::Disconnect()
{
    if (OperationInProgress("disconnect"))
    {
        return;
    }
    m_state.Update(
        [](SessionState& state)
        {
            state.ConnectionOperationActive(true);
            state.Activity(SessionActivity::Stopping);
            state.Busy(true);
            state.Error(std::nullopt);
        });
    m_vpnProfileController.Disconnect();
}

void SessionControllerImpl::Logout()
{
    if (OperationInProgress("logout"))
    {
        return;
    }
    m_state.Update(
        [](SessionState& state)
        {
            state.ConnectionOperationActive(true);
            state.Activity(SessionActivity::LoggingOut);
            state.Busy(true);
            state.Error(std::nullopt);
        });
    m_vpnProfileController.Logout();
}

void SessionControllerImpl::Refresh()
{
    if (m_state.ConnectionOperationActive())
    {
        return;
    }
    m_state.Update(
        [](SessionState& state)
        {
            state.Activity(SessionActivity::Checking);
            state.Busy(true);
        });
    m_vpnProfileController.Refresh();
}

void SessionControllerImpl::CancelActiveConnectionAttempt()
{
    m_interactiveAuthorizationController.Cancel();
    m_vpnProfileController.CancelConnect();
}

void SessionControllerImpl::BeginExitNodeChange()
{
    if (OperationInProgress("exit-node change"))
    {
        return;
    }
    m_state.Update(
        [](SessionState& state)
        {
            state.ConnectionOperationActive(true);
            state.Activity(SessionActivity::ChangingSettings);
            state.Busy(true);
            state.Error(std::nullopt);
        });
}

void SessionControllerImpl::FinishExitNodeChange(std::optional<UwpError::Code> error)
{
    m_state.Update(
        [&](SessionState& state)
        {
            state.ConnectionOperationActive(false);
            state.Activity(SessionActivity::Idle);
            state.Busy(false);
            state.Error(error);
        });
    if (error)
    {
        Refresh();
    }
}

} // namespace tailgate::uwp
