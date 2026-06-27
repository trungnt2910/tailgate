#pragma once

#include "tailgate/protocol/ControlRequests.h"

namespace tailgate::linux_frontend
{

[[nodiscard]] tailgate::protocol::HostInfo CollectHostInfo();

} // namespace tailgate::linux_frontend
