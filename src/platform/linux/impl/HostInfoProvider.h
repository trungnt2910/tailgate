#pragma once

#include <tailgate/control/client/HostInfoProvider.h>

namespace tailgate::linux_frontend::impl
{

class HostInfoProvider final : public tailgate::control::client::HostInfoProvider
{
public:
    [[nodiscard]] tailgate::control::client::HostInfo GetHostInfo() override;
};

} // namespace tailgate::linux_frontend::impl
