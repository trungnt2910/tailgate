#pragma once

#include <cstdint>
#include <optional>

#include <tailgate/base/Logger.h>

#include "common/UwpFormat.h"

#include "common/UwpError.h"

#include "app/controller/MainWindowController.h"
#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

class AuthorizationController;
class NavigationController;
class NodeAuthorizationDialogController;
class PingDialogController;
class ProfilePictureController;
class SessionController;
class SetOptionsController;
class SettingsController;
class SignInDialogController;

class MainWindowControllerImpl final : public MainWindowController
{
public:
    MainWindowControllerImpl(AuthorizationController& authorizationController,
                             NavigationController& navigationController,
                             NodeAuthorizationDialogController& nodeAuthorizationDialogController,
                             PingDialogController& pingDialogController,
                             ProfilePictureController& profilePictureController,
                             SessionController& sessionController,
                             SetOptionsController& setOptionsController,
                             SettingsController& settingsController,
                             SignInDialogController& signInDialogController);

    void Activate() override;
    void SetArguments(const tailgate::cli::Arguments& arguments) override;

private:
    void RunCommand(const tailgate::cli::Arguments& arguments);
    void OnAuthorizationChanged();
    void OnSessionChanged();
    void OnSignInChanged();
    void OnSettingsChanged();
    void ShowSignInDialog(std::optional<UwpError::Code> error = std::nullopt);

    AuthorizationController& m_authorizationController;
    NavigationController& m_navigationController;
    NodeAuthorizationDialogController& m_nodeAuthorizationDialogController;
    PingDialogController& m_pingDialogController;
    ProfilePictureController& m_profilePictureController;
    SessionController& m_sessionController;
    SetOptionsController& m_setOptionsController;
    SettingsController& m_settingsController;
    SignInDialogController& m_signInDialogController;
    std::optional<tailgate::cli::Arguments> m_arguments;
    std::uint64_t m_lastSignInRequest = 0;
    winrt::hstring m_lastAuthorizationPrompt;
    StateEventRegistration m_authorizationRegistration;
    StateEventRegistration m_sessionRegistration;
    StateEventRegistration m_signInRegistration;
    StateEventRegistration m_settingsRegistration;
    tailgate::base::Logger m_logger{"uwp-main-window-ctrl"};
};

} // namespace tailgate::uwp
