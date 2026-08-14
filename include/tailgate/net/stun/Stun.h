#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tailgate::net::stun
{

using TransactionId = std::array<std::uint8_t, 12>;

[[nodiscard]] std::vector<std::uint8_t> BuildBindingRequest(const TransactionId& transactionId);
[[nodiscard]] std::optional<std::string>
ParseMappedIpv4Endpoint(const std::vector<std::uint8_t>& response,
                        const TransactionId& transactionId);

} // namespace tailgate::net::stun
