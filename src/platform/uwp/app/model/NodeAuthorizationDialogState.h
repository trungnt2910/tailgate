#pragma once

#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

class NodeAuthorizationDialogState final : public ObservableState<NodeAuthorizationDialogState>
{
    TAILGATE_PROPERTY(Url, winrt::hstring);
    TAILGATE_PROPERTY(MachineApproval, bool);
    TAILGATE_PROPERTY(CancelRequested, bool);
};

} // namespace tailgate::uwp
