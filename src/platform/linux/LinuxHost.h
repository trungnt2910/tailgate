#pragma once

#include <tailgate/control/client/ControlRequests.h>

namespace tailgate::linux_frontend
{

[[nodiscard]] tailgate::control::client::HostInfo CollectHostInfo();

} // namespace tailgate::linux_frontend
