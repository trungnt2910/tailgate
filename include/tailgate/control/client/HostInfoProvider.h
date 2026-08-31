#pragma once

#include <tailgate/control/client/ControlRequests.h>

namespace tailgate::control::client
{

class HostInfoProvider
{
public:
    virtual ~HostInfoProvider();
    [[nodiscard]] virtual HostInfo GetHostInfo() = 0;

protected:
    HostInfoProvider() = default;
};

} // namespace tailgate::control::client
