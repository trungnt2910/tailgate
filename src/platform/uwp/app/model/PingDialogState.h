#pragma once

#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

enum class PingDialogError
{
    None,
    LocalAddress,
    InvalidAddress,
};

class PingDialogState final : public ObservableState<PingDialogState>
{
    TAILGATE_PROPERTY(DeviceName, winrt::hstring);
    TAILGATE_PROPERTY(Error, PingDialogError);
    TAILGATE_PROPERTY(ErrorDetail, winrt::hstring);
};

} // namespace tailgate::uwp
