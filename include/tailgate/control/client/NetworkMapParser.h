#pragma once

#include <string>

#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::control::client
{

class NetworkMapParser final
{
public:
    [[nodiscard]] static tailgate::types::netmap::NetworkConfig Parse(const std::string& json);
    [[nodiscard]] static bool ApplyUpdate(tailgate::types::netmap::NetworkConfig& config,
                                          const std::string& json);
};

} // namespace tailgate::control::client
