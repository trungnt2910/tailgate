#include "app/controller/impl/SignInDialogControllerImpl.h"

namespace tailgate::uwp
{

SignInDialogControllerImpl::SignInDialogControllerImpl(ContentDialogController& dialogController)
    : m_dialogController(dialogController)
{
}

const SignInDialogState& SignInDialogControllerImpl::GetState() const noexcept
{
    return m_state;
}

void SignInDialogControllerImpl::Show(const winrt::hstring& tailgateServer,
                                      const winrt::hstring& authKey,
                                      const winrt::hstring& hostname,
                                      std::optional<UwpError::Code> error)
{
    m_state.Update(
        [&](SignInDialogState& state)
        {
            state.TailgateServer(tailgateServer);
            state.AuthKey(authKey);
            state.Hostname(hostname);
            state.Error(error);
            state.AdvancedExpanded(!authKey.empty() || !hostname.empty());
            state.AdvancedHovered(false);
            state.ValidationErrorVisible(false);
            state.Accepted(false);
        });
    m_dialogController.ShowDialog(ContentDialogControllerState::SignIn);
}

void SignInDialogControllerImpl::Hide()
{
    m_dialogController.HideDialog(ContentDialogControllerState::SignIn);
}

void SignInDialogControllerImpl::OnClosed(controls::ContentDialogResult result)
{
    m_state.Accepted(result == controls::ContentDialogResult::Primary);
}

void SignInDialogControllerImpl::OnTailgateServerChanged(const winrt::hstring& value)
{
    m_state.TailgateServer(value);
}

void SignInDialogControllerImpl::OnAuthKeyChanged(const winrt::hstring& value)
{
    m_state.AuthKey(value);
}

void SignInDialogControllerImpl::OnHostnameChanged(const winrt::hstring& value)
{
    m_state.Hostname(value);
}

void SignInDialogControllerImpl::OnAdvancedClicked()
{
    m_state.AdvancedExpanded(!m_state.AdvancedExpanded());
}

void SignInDialogControllerImpl::OnAdvancedPointerEntered()
{
    m_state.AdvancedHovered(true);
}

void SignInDialogControllerImpl::OnAdvancedPointerExited()
{
    m_state.AdvancedHovered(false);
}

void SignInDialogControllerImpl::OnPrimaryButtonClick()
{
    const bool invalid = m_state.TailgateServer().empty();
    m_state.ValidationErrorVisible(invalid);
}

} // namespace tailgate::uwp
