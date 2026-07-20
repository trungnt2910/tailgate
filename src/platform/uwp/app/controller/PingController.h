#pragma once

#include "app/model/PingState.h"
#include "common/UwpAliases.h"

namespace tailgate::uwp
{

class PingController
{
public:
    virtual ~PingController() = default;

    [[nodiscard]] virtual const PingState& GetState() const noexcept = 0;
    virtual void Start(const winrt::hstring& address, const winrt::hstring& selfAddress) = 0;
    virtual void Stop() noexcept = 0;
};

} // namespace tailgate::uwp
