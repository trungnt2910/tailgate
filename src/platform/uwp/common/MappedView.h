#pragma once

#include <winrt/base.h>

namespace tailgate::uwp
{

namespace detail
{

struct MappedViewTraits
{
    using type = void*;

    static void close(type value) noexcept;

    [[nodiscard]] static constexpr type invalid() noexcept
    {
        return nullptr;
    }
};

} // namespace detail

using MappedView = winrt::handle_type<detail::MappedViewTraits>;

} // namespace tailgate::uwp
