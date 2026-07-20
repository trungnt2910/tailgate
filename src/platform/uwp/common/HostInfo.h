#pragma once

#include <tailgate/protocol/ControlRequests.h>

namespace tailgate::uwp
{

// Collects the machine identity advertised to control: the hostname (honoring the user
// override), the UWP OS version, and the CPU architecture.
[[nodiscard]] protocol::HostInfo BuildHostInfo();

} // namespace tailgate::uwp
