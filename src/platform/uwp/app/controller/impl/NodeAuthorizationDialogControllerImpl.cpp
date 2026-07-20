#include "app/controller/impl/NodeAuthorizationDialogControllerImpl.h"

#include <winrt/Windows.System.h>

namespace tailgate::uwp
{
namespace winsystem = winrt::Windows::System;

NodeAuthorizationDialogControllerImpl::NodeAuthorizationDialogControllerImpl(
    ContentDialogController& dialogController)
    : m_dialogController(dialogController)
{
}

const NodeAuthorizationDialogState& NodeAuthorizationDialogControllerImpl::GetState() const noexcept
{
    return m_state;
}

void NodeAuthorizationDialogControllerImpl::Show(const winrt::hstring& authUrl,
                                                 bool machineApproval)
{
    if (m_state.Url() == authUrl &&
        m_dialogController.GetState().Current() == ContentDialogControllerState::NodeAuthorization)
    {
        return;
    }

    m_state.Update(
        [&](NodeAuthorizationDialogState& state)
        {
            state.Url(authUrl);
            state.MachineApproval(machineApproval);
            state.CancelRequested(false);
        });
    m_dialogController.ShowDialog(ContentDialogControllerState::NodeAuthorization);
}

void NodeAuthorizationDialogControllerImpl::Hide()
{
    m_dialogController.HideDialog(ContentDialogControllerState::NodeAuthorization);
}

void NodeAuthorizationDialogControllerImpl::OnPrimaryButtonClick()
{
    (void)winsystem::Launcher::LaunchUriAsync(foundation::Uri(m_state.Url()));
}

void NodeAuthorizationDialogControllerImpl::OnCloseButtonClick()
{
    m_state.CancelRequested(true);
}

} // namespace tailgate::uwp
