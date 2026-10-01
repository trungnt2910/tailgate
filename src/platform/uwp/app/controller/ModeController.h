#pragma once

#include "app/model/ModeState.h"

namespace tailgate::uwp
{

class ModeController
{
public:
    virtual ~ModeController() = default;
    [[nodiscard]] virtual const ModeState& GetState() const noexcept = 0;
    virtual void SetRelay(const winrt::hstring& relayUrl) = 0;
};

} // namespace tailgate::uwp
