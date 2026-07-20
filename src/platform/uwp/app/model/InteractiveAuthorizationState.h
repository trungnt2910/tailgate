#pragma once

#include <optional>

#include "common/UwpError.h"

#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

enum class InteractiveAuthorizationStatus
{
    Idle,
    Listening,
    LoginRequired,
    MachineApprovalRequired,
    Authorized,
    Failed,
    Cancelled,
};

class InteractiveAuthorizationState final : public ObservableState<InteractiveAuthorizationState>
{
    TAILGATE_PROPERTY(Status, InteractiveAuthorizationStatus);
    TAILGATE_PROPERTY(Url, winrt::hstring);
    TAILGATE_PROPERTY(TailgateServer, winrt::hstring);
    TAILGATE_PROPERTY(Error, std::optional<UwpError::Code>);
};

} // namespace tailgate::uwp
