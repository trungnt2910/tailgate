#pragma once

#include <nlohmann/json_fwd.hpp>

#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::control::client
{

void ApplySelfAddresses(types::netmap::NetworkConfig& config, const nlohmann::json& node);

} // namespace tailgate::control::client
