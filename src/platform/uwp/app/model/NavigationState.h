#pragma once

#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

enum class NavigationControllerState
{
    Home,
    Settings,
    Accounts,
    Device,
    ExitNodes,
};

class NavigationState final : public ObservableState<NavigationState>
{
    TAILGATE_PROPERTY(Current, NavigationControllerState);
    TAILGATE_PROPERTY(CanGoBack, bool);
};

} // namespace tailgate::uwp
