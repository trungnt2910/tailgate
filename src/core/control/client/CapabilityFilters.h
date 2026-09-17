#pragma once

#include <exception>

#include <nlohmann/json_fwd.hpp>

#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::control::client
{

class CapabilityFilterError final : public std::exception
{
public:
    [[nodiscard]] const char* what() const noexcept override;
};

[[nodiscard]] bool ApplyCapabilityFilterUpdate(types::netmap::NetworkConfig& configuration,
                                               const nlohmann::json& map);

} // namespace tailgate::control::client
