#pragma once

#include <string>

#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::control::client
{

[[nodiscard]] tailgate::types::netmap::NetworkConfig ParseNetworkMap(const std::string& json);
[[nodiscard]] bool ApplyNetworkMapUpdate(tailgate::types::netmap::NetworkConfig& config,
                                         const std::string& json);

} // namespace tailgate::control::client
