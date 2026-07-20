#pragma once

#include "app/controller/DevicePageController.h"

namespace tailgate::uwp
{

class DevicePageControllerImpl final : public DevicePageController
{
public:
    [[nodiscard]] const DevicePageState& GetState() const noexcept override;
    void SelectDevice(const winrt::hstring& deviceId) override;

private:
    DevicePageState m_state;
};

} // namespace tailgate::uwp
