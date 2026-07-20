#pragma once

#include <cstddef>
#include <string_view>

namespace tailgate::uwp
{

struct ResourceKey final
{
    std::wstring_view Name;
};

template <std::size_t ArgumentCount>
struct ResourceFormatKey final
{
    static constexpr std::size_t Arity = ArgumentCount;
    std::wstring_view Name;
};

} // namespace tailgate::uwp
