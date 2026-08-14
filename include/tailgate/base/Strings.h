#pragma once

#include <string_view>

namespace tailgate::base
{

[[nodiscard]] std::string_view TrimEnd(std::string_view value) noexcept;

} // namespace tailgate::base
