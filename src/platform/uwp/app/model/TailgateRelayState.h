#pragma once

#include <cstdint>
#include <optional>

#include "common/UwpError.h"

#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

class TailgateRelayState final : public ObservableState<TailgateRelayState>
{
    TAILGATE_PROPERTY(OperationId, std::uint64_t);
    TAILGATE_PROPERTY(RequestedTailgateServer, winrt::hstring);
    TAILGATE_PROPERTY(TailgateServer, winrt::hstring);
    TAILGATE_PROPERTY(Busy, bool);
    TAILGATE_PROPERTY(Error, std::optional<UwpError::Code>);
};

} // namespace tailgate::uwp
