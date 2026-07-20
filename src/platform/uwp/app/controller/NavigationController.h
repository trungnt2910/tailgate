#pragma once

#include "app/model/NavigationState.h"

namespace tailgate::uwp
{

class NavigationController
{
public:
    virtual ~NavigationController() = default;

    [[nodiscard]] virtual const NavigationState& GetState() const noexcept = 0;
    virtual void Home() = 0;
    virtual void Back() = 0;
    virtual void OpenPage(NavigationControllerState page) = 0;
};

} // namespace tailgate::uwp
