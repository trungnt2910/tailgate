#pragma once

#include <optional>

#include "app/controller/DevicePageController.h"

namespace tailgate::uwp::tests
{

class FakeDevicePageController final : public DevicePageController
{
public:
    [[nodiscard]] const DevicePageState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] DevicePageState& GetState() noexcept
    {
        return m_state;
    }

    void SelectDevice(const winrt::hstring& deviceId) override
    {
        SelectDeviceArgument = deviceId;
        m_state.SelectedDeviceId(deviceId);
    }

    std::optional<winrt::hstring> SelectDeviceArgument;

private:
    DevicePageState m_state;
};

} // namespace tailgate::uwp::tests
