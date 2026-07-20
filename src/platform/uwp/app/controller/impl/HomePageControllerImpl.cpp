#include "app/controller/impl/HomePageControllerImpl.h"

namespace tailgate::uwp
{

const HomePageState& HomePageControllerImpl::GetState() const noexcept
{
    return m_state;
}

void HomePageControllerImpl::SearchText(const winrt::hstring& value)
{
    m_state.SearchText(value);
}

} // namespace tailgate::uwp
