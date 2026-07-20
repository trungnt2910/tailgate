#include "app/controller/impl/DevicePageControllerImpl.h"

namespace tailgate::uwp
{

const DevicePageState& DevicePageControllerImpl::GetState() const noexcept
{
    return m_state;
}

void DevicePageControllerImpl::SelectDevice(const winrt::hstring& deviceId)
{
    m_state.SelectedDeviceId(deviceId);
}

} // namespace tailgate::uwp
