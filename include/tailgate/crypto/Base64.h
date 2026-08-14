#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tailgate::crypto
{

[[nodiscard]] std::string Base64Encode(const std::vector<std::uint8_t>& data);
[[nodiscard]] std::vector<std::uint8_t> Base64Decode(const std::string& text);

} // namespace tailgate::crypto
