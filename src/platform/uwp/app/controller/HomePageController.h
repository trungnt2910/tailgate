#pragma once

#include <winrt/base.h>

#include "app/model/HomePageState.h"

namespace tailgate::uwp
{

class HomePageController
{
public:
    virtual ~HomePageController() = default;

    [[nodiscard]] virtual const HomePageState& GetState() const noexcept = 0;
    virtual void SearchText(const winrt::hstring& value) = 0;
};

} // namespace tailgate::uwp
