#pragma once

#include "app/view/View.h"

namespace tailgate::uwp
{

class MainWindowView : public View
{
public:
    virtual ~MainWindowView() = default;

    virtual void Show() = 0;
};

} // namespace tailgate::uwp
