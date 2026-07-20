#pragma once

#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

enum class ContentDialogControllerState
{
    None,
    SignIn,
    NodeAuthorization,
    Ping,
};

class ContentDialogState final : public ObservableState<ContentDialogState>
{
    TAILGATE_PROPERTY(Current, ContentDialogControllerState);
};

} // namespace tailgate::uwp
