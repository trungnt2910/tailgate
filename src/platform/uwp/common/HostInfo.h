#pragma once

#include <tailgate/control/client/ControlRequests.h>

namespace tailgate::uwp
{

// Collects the machine identity advertised to control: the hostname (honoring the user
// override), the UWP OS version, and the CPU architecture.
[[nodiscard]] tailgate::control::client::HostInfo BuildHostInfo();

} // namespace tailgate::uwp
