#pragma once

#include <stop_token>

#include "common/UwpAliases.h"

namespace tailgate::uwp
{

[[nodiscard]] vpn::IVpnPlugIn CreateTailgateVpnPlugin();
void ProcessTailgateVpnEvent(const vpn::IVpnPlugIn& plugin,
                             const foundation::IInspectable& triggerDetails,
                             std::stop_token cancellation);

} // namespace tailgate::uwp
