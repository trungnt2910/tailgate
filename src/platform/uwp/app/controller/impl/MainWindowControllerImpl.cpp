#include "app/controller/impl/MainWindowControllerImpl.h"

#include <algorithm>

#include "app/controller/AuthorizationController.h"
#include "app/controller/NavigationController.h"
#include "app/controller/NodeAuthorizationDialogController.h"
#include "app/controller/PingDialogController.h"
#include "app/controller/ProfilePictureController.h"
#include "app/controller/SessionController.h"
#include "app/controller/SetOptionsController.h"
#include "app/controller/SettingsController.h"
#include "app/controller/SignInDialogController.h"

namespace tailgate::uwp
{

MainWindowControllerImpl::MainWindowControllerImpl(
    AuthorizationController& authorizationController,
    NavigationController& navigationController,
    NodeAuthorizationDialogController& nodeAuthorizationDialogController,
    PingDialogController& pingDialogController,
    ProfilePictureController& profilePictureController,
    SessionController& sessionController,
    SetOptionsController& setOptionsController,
    SettingsController& settingsController,
    SignInDialogController& signInDialogController)
    : m_authorizationController(authorizationController),
      m_navigationController(navigationController),
      m_nodeAuthorizationDialogController(nodeAuthorizationDialogController),
      m_pingDialogController(pingDialogController),
      m_profilePictureController(profilePictureController),
      m_sessionController(sessionController),
      m_setOptionsController(setOptionsController),
      m_settingsController(settingsController),
      m_signInDialogController(signInDialogController)
{
    m_sessionRegistration = m_sessionController.GetState().Subscribe(
        [this](const auto&, const auto&)
        {
            OnSessionChanged();
        });
    m_authorizationRegistration = m_authorizationController.GetState().Subscribe(
        [this](const auto&, const auto&)
        {
            OnAuthorizationChanged();
        });
    m_settingsRegistration = m_settingsController.GetState().Subscribe(
        [this](const auto&, const auto&)
        {
            OnSettingsChanged();
        });
    m_signInRegistration = m_signInDialogController.GetState().Subscribe(
        [this](const auto&, const auto&)
        {
            OnSignInChanged();
        });
}

void MainWindowControllerImpl::Activate()
{
    m_settingsController.Reload();
    m_navigationController.Home();
    m_profilePictureController.Load();
    m_sessionController.Refresh();
    if (m_arguments)
    {
        RunCommand(*m_arguments);
        m_arguments.reset();
    }
}

void MainWindowControllerImpl::SetArguments(const tailgate::cli::Arguments& arguments)
{
    m_arguments = arguments;
}

void MainWindowControllerImpl::RunCommand(const tailgate::cli::Arguments& arguments)
{
    switch (arguments.SelectedCommand)
    {
    case tailgate::cli::Command::Up:
    {
        if (arguments.Up.HostnameSet)
        {
            m_settingsController.SetHostname(winrt::to_hstring(arguments.Up.Hostname));
        }
        const winrt::hstring authKey = winrt::to_hstring(arguments.Up.AuthKey);
        winrt::hstring server = winrt::to_hstring(arguments.Up.TailgateUrl);
        if (server.empty())
        {
            m_settingsController.Reload();
            server = m_settingsController.GetState().TailgateServer();
        }
        m_authorizationController.SetPendingAuthentication(server, authKey);
        if (!server.empty() &&
            (!authKey.empty() || m_settingsController.GetState().HasStoredProfile()))
        {
            m_sessionController.Connect(server, authKey, true);
            return;
        }
        ShowSignInDialog();
        return;
    }
    case tailgate::cli::Command::Down:
        m_sessionController.Disconnect();
        return;
    case tailgate::cli::Command::Logout:
        m_sessionController.Logout();
        return;
    case tailgate::cli::Command::Set:
        m_setOptionsController.Apply(arguments.Set);
        return;
    case tailgate::cli::Command::Ping:
    {
        const winrt::hstring target = winrt::to_hstring(arguments.Ping.Target);
        const SettingsState& settings = m_settingsController.GetState();
        const auto device = std::find_if(settings.Devices().begin(),
                                         settings.Devices().end(),
                                         [&target](const UwpDevice& candidate)
                                         {
                                             return candidate.Address == target ||
                                                    candidate.Name == target ||
                                                    candidate.ShortName() == target;
                                         });
        if (device == settings.Devices().end())
        {
            m_logger.LogWarning("ping target is not a known device: {}", target);
            return;
        }
        winrt::hstring selfAddress = settings.SelfAddress();
        if (selfAddress.empty() && !settings.Devices().empty())
        {
            selfAddress = settings.Devices().front().Address;
        }
        const winrt::hstring deviceName =
            device->Name.empty() ? device->Address : device->ShortName();
        m_pingDialogController.Show(deviceName, device->Address, selfAddress);
        return;
    }
    default:
        m_logger.LogWarning("command is not supported on UWP");
        return;
    }
}

void MainWindowControllerImpl::OnAuthorizationChanged()
{
    const AuthorizationControllerState& authorization = m_authorizationController.GetState();
    if (!authorization.PromptUrl().empty() &&
        authorization.PromptUrl() != m_lastAuthorizationPrompt)
    {
        m_lastAuthorizationPrompt = authorization.PromptUrl();
        m_nodeAuthorizationDialogController.Show(authorization.PromptUrl(),
                                                 authorization.MachineApproval());
        return;
    }
    if (authorization.PromptUrl().empty())
    {
        m_lastAuthorizationPrompt.clear();
        m_signInDialogController.Hide();
        m_nodeAuthorizationDialogController.Hide();
        m_pingDialogController.Hide();
    }
}

void MainWindowControllerImpl::OnSessionChanged()
{
    const SessionState& session = m_sessionController.GetState();
    if (session.SignInRequest() != m_lastSignInRequest)
    {
        m_lastSignInRequest = session.SignInRequest();
        ShowSignInDialog(session.Error());
    }
    if (!session.Connected() && !m_settingsController.GetState().HasStoredProfile())
    {
        m_profilePictureController.Clear();
    }
}

void MainWindowControllerImpl::OnSettingsChanged()
{
    m_profilePictureController.Load();
}

void MainWindowControllerImpl::OnSignInChanged()
{
    if (!m_signInDialogController.GetState().Accepted())
    {
        return;
    }
    m_authorizationController.AcceptAuthentication();
    m_sessionController.Connect(m_signInDialogController.GetState().TailgateServer(),
                                m_signInDialogController.GetState().AuthKey(),
                                true);
}

void MainWindowControllerImpl::ShowSignInDialog(std::optional<UwpError::Code> error)
{
    const AuthorizationControllerState& authorization = m_authorizationController.GetState();
    const winrt::hstring tailgateServer = authorization.PendingTailgateServer().empty()
                                              ? m_settingsController.GetState().TailgateServer()
                                              : authorization.PendingTailgateServer();
    const winrt::hstring hostname = authorization.PendingHostname()
                                        ? *authorization.PendingHostname()
                                        : m_settingsController.GetState().Hostname();
    m_signInDialogController.Show(tailgateServer, authorization.PendingAuthKey(), hostname, error);
}

} // namespace tailgate::uwp
