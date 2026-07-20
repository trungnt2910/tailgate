#pragma once

#include <vector>

#include "app/controller/NavigationController.h"

namespace tailgate::uwp
{

class NavigationControllerImpl final : public NavigationController
{
public:
    [[nodiscard]] const NavigationState& GetState() const noexcept override;
    void Home() override;
    void Back() override;
    void OpenPage(NavigationControllerState page) override;

private:
    struct Entry
    {
        NavigationControllerState Page = NavigationControllerState::Home;
    };

    void Navigate(Entry entry);
    void Publish(const Entry& entry);

    Entry m_current;
    std::vector<Entry> m_stack;
    NavigationState m_state;
};

} // namespace tailgate::uwp
