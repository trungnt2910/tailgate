#pragma once

#include "app/model/DevicePageState.h"

namespace tailgate::uwp
{

class DevicePageController
{
public:
    virtual ~DevicePageController() = default;

    [[nodiscard]] virtual const DevicePageState& GetState() const noexcept = 0;
    virtual void SelectDevice(const winrt::hstring& deviceId) = 0;
};

} // namespace tailgate::uwp
