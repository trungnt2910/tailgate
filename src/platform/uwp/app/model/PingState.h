#pragma once

#include <vector>

#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

enum class PingStatus
{
    Starting,
    Success,
    NoMatchingPeer,
    Timeout,
    Failed,
};

class PingState final : public ObservableState<PingState>
{
    TAILGATE_PROPERTY(Samples, std::vector<double>);
    TAILGATE_PROPERTY(LatencyMilliseconds, double);
    TAILGATE_PROPERTY(Direct, bool);
    TAILGATE_PROPERTY(Relay, winrt::hstring);
    TAILGATE_PROPERTY(Status, PingStatus);
};

} // namespace tailgate::uwp
