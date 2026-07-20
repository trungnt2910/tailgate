#pragma once

#include <optional>

#include "common/UwpError.h"

#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

class ControlPlaneState final : public ObservableState<ControlPlaneState>
{
    TAILGATE_PROPERTY(Busy, bool);
    TAILGATE_PROPERTY(Error, std::optional<UwpError::Code>);
};

} // namespace tailgate::uwp
