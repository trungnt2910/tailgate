#include "app/controller/impl/AuthorizationControllerImpl.h"

#include <utility>

#include "app/controller/SettingsController.h"
#include "app/controller/SignInDialogController.h"

namespace tailgate::uwp
{

AuthorizationControllerImpl::AuthorizationControllerImpl(
    SettingsController& settingsController, SignInDialogController& signInDialogController)
    : m_settingsController(settingsController), m_signInDialogController(signInDialogController)
{
}

const AuthorizationControllerState& AuthorizationControllerImpl::GetState() const noexcept
{
    return m_state;
}

void AuthorizationControllerImpl::SetPendingAuthentication(const winrt::hstring& tailgateServer,
                                                           const winrt::hstring& authKey)
{
    m_state.Update(
        [&](AuthorizationControllerState& state)
        {
            state.PendingTailgateServer(tailgateServer);
            state.PendingAuthKey(authKey);
        });
}

void AuthorizationControllerImpl::AcceptAuthentication()
{
    const SignInDialogState& authentication = m_signInDialogController.GetState();
    m_settingsController.SetHostname(authentication.Hostname());
    m_state.Update(
        [&](AuthorizationControllerState& state)
        {
            state.PendingTailgateServer(authentication.TailgateServer());
            state.PendingAuthKey(authentication.AuthKey());
            state.PendingHostname(authentication.Hostname());
        });
}

void AuthorizationControllerImpl::ClearPendingAuthentication()
{
    m_state.Update(
        [](AuthorizationControllerState& state)
        {
            state.PendingTailgateServer({});
            state.PendingAuthKey({});
            state.PendingHostname(std::nullopt);
        });
}

void AuthorizationControllerImpl::Cache(AuthorizationCache authorization)
{
    m_state.Update(
        [&](AuthorizationControllerState& state)
        {
            state.Authorization(std::move(authorization));
            state.MatchedAuthorization(std::nullopt);
        });
}

void AuthorizationControllerImpl::FindCached(const winrt::hstring& tailgateServer,
                                             const winrt::hstring& authKey,
                                             const winrt::hstring& hostname)
{
    m_state.Update(
        [&](AuthorizationControllerState& state)
        {
            state.MatchedAuthorization(std::nullopt);
            if (!state.Authorization())
            {
                return;
            }
            if (state.Authorization()->TailgateServer != tailgateServer ||
                state.Authorization()->AuthKey != authKey ||
                state.Authorization()->Hostname != hostname)
            {
                state.Authorization(std::nullopt);
                return;
            }
            state.MatchedAuthorization(state.Authorization());
        });
}

void AuthorizationControllerImpl::RequestPrompt(const winrt::hstring& url, bool machineApproval)
{
    m_state.Update(
        [&](AuthorizationControllerState& state)
        {
            state.PromptUrl(url);
            state.MachineApproval(machineApproval);
        });
}

void AuthorizationControllerImpl::Clear()
{
    m_state.Update(
        [](AuthorizationControllerState& state)
        {
            state.Authorization(std::nullopt);
            state.MatchedAuthorization(std::nullopt);
            state.PromptUrl({});
            state.MachineApproval(false);
        });
}

} // namespace tailgate::uwp
