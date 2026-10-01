#pragma once

#include "app/model/ModeState.h"

namespace tailgate::uwp
{

class ModeRpcController
{
public:
    virtual ~ModeRpcController() = default;
    [[nodiscard]] virtual const ModeRpcState& GetState() const noexcept = 0;
    virtual void Request(const winrt::hstring& selfAddress, const winrt::hstring& relayUrl) = 0;
};

} // namespace tailgate::uwp
