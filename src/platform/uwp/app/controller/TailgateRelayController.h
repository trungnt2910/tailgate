#pragma once

#include <cstdint>

#include "app/model/TailgateRelayState.h"

namespace tailgate::uwp
{

class TailgateRelayController
{
public:
    virtual ~TailgateRelayController() = default;

    [[nodiscard]] virtual const TailgateRelayState& GetState() const noexcept = 0;
    virtual void Preflight(std::uint64_t operationId, const winrt::hstring& tailgateServer) = 0;
};

} // namespace tailgate::uwp
