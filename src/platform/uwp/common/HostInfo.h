#pragma once

#include <tailgate/control/client/HostInfoProvider.h>

namespace tailgate::uwp
{

// Collects the machine identity advertised to control: the hostname (honoring the user
// override), the UWP OS version, and the CPU architecture.
[[nodiscard]] tailgate::control::client::HostInfo BuildHostInfo();

class HostInfoProvider final : public tailgate::control::client::HostInfoProvider
{
public:
    [[nodiscard]] tailgate::control::client::HostInfo GetHostInfo() override;
};

} // namespace tailgate::uwp
