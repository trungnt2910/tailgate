#pragma once

#include <cstddef>

#include "app/controller/NavigationController.h"

namespace tailgate::uwp::tests
{

class FakeNavigationController final : public NavigationController
{
public:
    using Interface = NavigationController;

    [[nodiscard]] const NavigationState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] NavigationState& GetState() noexcept
    {
        return m_state;
    }

    void Home() override
    {
        m_state.Update(
            [](NavigationState& state)
            {
                state.Current(NavigationControllerState::Home);
                state.CanGoBack(false);
            });
    }

    void Back() override
    {
        ++BackCount;
    }

    void OpenPage(NavigationControllerState page) override
    {
        m_state.Update(
            [&](NavigationState& state)
            {
                state.Current(page);
                state.CanGoBack(true);
            });
    }

    std::size_t BackCount = 0;

private:
    NavigationState m_state;
};

} // namespace tailgate::uwp::tests
