#pragma once

#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

enum class ExitNodeChangeStatus
{
    Success,
    Rejected,
    Timeout,
    Failed,
};

class ExitNodeState final : public ObservableState<ExitNodeState>
{
    TAILGATE_PROPERTY(Current, winrt::hstring);
    TAILGATE_PROPERTY(Selection, winrt::hstring);
    TAILGATE_PROPERTY(ChangeStatus, ExitNodeChangeStatus);
};

} // namespace tailgate::uwp
