#pragma once

#include <optional>

#include "common/UwpError.h"

#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

enum class VpnProfileActivity
{
    Idle,
    Connecting,
    Disconnecting,
    LoggingOut,
    Discarding,
    Refreshing,
};

class VpnProfileState final : public ObservableState<VpnProfileState>
{
    TAILGATE_PROPERTY(Activity, VpnProfileActivity);
    TAILGATE_PROPERTY(Busy, bool);
    TAILGATE_PROPERTY(Connected, bool);
    TAILGATE_PROPERTY(Error, std::optional<UwpError::Code>);
};

} // namespace tailgate::uwp
