#include "app/controller/impl/NavigationControllerImpl.h"

#include <utility>

namespace tailgate::uwp
{

const NavigationState& NavigationControllerImpl::GetState() const noexcept
{
    return m_state;
}

void NavigationControllerImpl::Home()
{
    m_stack.clear();
    m_current = Entry{};
    Publish(m_current);
}

void NavigationControllerImpl::Back()
{
    if (m_stack.empty())
    {
        return;
    }
    m_current = std::move(m_stack.back());
    m_stack.pop_back();
    Publish(m_current);
}

void NavigationControllerImpl::OpenPage(NavigationControllerState page)
{
    Entry entry;
    entry.Page = page;
    Navigate(std::move(entry));
}

void NavigationControllerImpl::Navigate(Entry entry)
{
    m_stack.push_back(m_current);
    m_current = std::move(entry);
    Publish(m_current);
}

void NavigationControllerImpl::Publish(const Entry& entry)
{
    m_state.Update(
        [&](NavigationState& state)
        {
            state.Current(entry.Page);
            state.CanGoBack(!m_stack.empty());
        });
}

} // namespace tailgate::uwp
