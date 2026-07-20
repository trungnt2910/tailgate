#pragma once

#include <winrt/base.h>

namespace tailgate::uwp
{

class ClipboardController
{
public:
    virtual ~ClipboardController() = default;

    virtual void SetText(const winrt::hstring& value) = 0;
};

} // namespace tailgate::uwp
