#pragma once

#include "app/view/View.h"

namespace tailgate::uwp
{

class PageView : public View
{
public:
    virtual ~PageView() = default;

    [[nodiscard]] virtual xaml::UIElement Page() const = 0;
};

} // namespace tailgate::uwp
