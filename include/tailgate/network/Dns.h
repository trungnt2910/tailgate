#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tailgate::network
{

[[nodiscard]] std::optional<std::string> DnsQueryName(const std::vector<std::uint8_t>& message);
[[nodiscard]] bool DnsNameHasSuffix(const std::string& name, const std::string& suffix);

} // namespace tailgate::network
