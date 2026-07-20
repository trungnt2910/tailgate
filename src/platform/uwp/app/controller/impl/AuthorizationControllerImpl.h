#pragma once

#include "app/controller/AuthorizationController.h"

namespace tailgate::uwp
{

class SettingsController;
class SignInDialogController;

class AuthorizationControllerImpl final : public AuthorizationController
{
public:
    AuthorizationControllerImpl(SettingsController& settingsController,
                                SignInDialogController& signInDialogController);

    [[nodiscard]] const AuthorizationControllerState& GetState() const noexcept override;
    void SetPendingAuthentication(const winrt::hstring& tailgateServer,
                                  const winrt::hstring& authKey) override;
    void AcceptAuthentication() override;
    void ClearPendingAuthentication() override;
    void Cache(AuthorizationCache authorization) override;
    void FindCached(const winrt::hstring& tailgateServer,
                    const winrt::hstring& authKey,
                    const winrt::hstring& hostname) override;
    void RequestPrompt(const winrt::hstring& url, bool machineApproval) override;
    void Clear() override;

private:
    SettingsController& m_settingsController;
    SignInDialogController& m_signInDialogController;
    AuthorizationControllerState m_state;
};

} // namespace tailgate::uwp
