#pragma once

#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

class DevicePageState final : public ObservableState<DevicePageState>
{
    TAILGATE_PROPERTY(SelectedDeviceId, winrt::hstring);
};

} // namespace tailgate::uwp
