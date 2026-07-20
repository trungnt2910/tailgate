#include "app/controller/impl/ContentDialogControllerImpl.h"

namespace tailgate::uwp
{

const ContentDialogState& ContentDialogControllerImpl::GetState() const noexcept
{
    return m_state;
}

void ContentDialogControllerImpl::ShowDialog(ContentDialogControllerState dialog)
{
    m_state.Current(dialog);
}

void ContentDialogControllerImpl::HideDialog(ContentDialogControllerState dialog)
{
    if (m_state.Current() == dialog)
    {
        m_state.Current(ContentDialogControllerState::None);
    }
}

} // namespace tailgate::uwp
