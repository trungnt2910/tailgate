#pragma once

#include <string_view>

namespace tailgate
{

[[nodiscard]] std::string_view TrimEnd(std::string_view value) noexcept;

} // namespace tailgate
