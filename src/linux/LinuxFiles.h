#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace tailgate::linux_frontend
{

[[nodiscard]] std::string ReadTextFile(const std::string& path);
[[nodiscard]] std::vector<std::uint8_t> ReadBinaryFile(const std::string& path);

} // namespace tailgate::linux_frontend
