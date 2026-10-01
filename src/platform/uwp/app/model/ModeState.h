#pragma once

#include "app/model/ObservableState.h"
#include "common/UwpAppServiceProtocol.h"

namespace tailgate::uwp
{

class ModeState final : public ObservableState<ModeState>
{
public:
    TAILGATE_PROPERTY(Transition, tailgate::ipn::ipnlocal::TransitionStatus);
    TAILGATE_PROPERTY(Busy, bool);
    TAILGATE_PROPERTY(Result, app_service::Status);
    TAILGATE_PROPERTY(RelayUrl, winrt::hstring);
};

class ModeRpcState final : public ObservableState<ModeRpcState>
{
public:
    TAILGATE_PROPERTY(Response, std::optional<app_service::ModeResponse>);
};

} // namespace tailgate::uwp
