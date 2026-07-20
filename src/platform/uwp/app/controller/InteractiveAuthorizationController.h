#pragma once

#include "app/model/InteractiveAuthorizationState.h"

namespace tailgate::uwp
{

class InteractiveAuthorizationController
{
public:
    virtual ~InteractiveAuthorizationController() = default;

    [[nodiscard]] virtual const InteractiveAuthorizationState& GetState() const noexcept = 0;
    virtual void Listen(const winrt::hstring& tailgateServer) = 0;
    virtual void Stop() = 0;
    virtual void Cancel() = 0;
};

} // namespace tailgate::uwp
