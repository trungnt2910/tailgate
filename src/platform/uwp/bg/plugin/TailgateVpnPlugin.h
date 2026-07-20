#pragma once

#include "common/UwpAliases.h"

namespace tailgate::uwp
{

[[nodiscard]] vpn::IVpnPlugIn CreateTailgateVpnPlugin();

} // namespace tailgate::uwp
