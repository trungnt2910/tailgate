#pragma once

#include "app/controller/ClipboardController.h"

namespace tailgate::uwp
{

class ClipboardControllerImpl final : public ClipboardController
{
public:
    void SetText(const winrt::hstring& value) override;
};

} // namespace tailgate::uwp
