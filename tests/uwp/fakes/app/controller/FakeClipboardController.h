#pragma once

#include <optional>

#include "app/controller/ClipboardController.h"

namespace tailgate::uwp::tests
{

class FakeClipboardController final : public ClipboardController
{
public:
    void SetText(const winrt::hstring& value) override
    {
        LastText = value;
    }

    std::optional<winrt::hstring> LastText;
};

} // namespace tailgate::uwp::tests
