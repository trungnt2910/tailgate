#pragma once

#include <format>
#include <string_view>

#include <winrt/base.h>

#include "common/ResourceKey.h"
#include "common/UwpError.h"

namespace tailgate::uwp
{

class ResourceLoader
{
public:
    virtual ~ResourceLoader() = default;

    [[nodiscard]] virtual winrt::hstring Get(const ResourceKey& key) const = 0;
    [[nodiscard]] winrt::hstring Get(UwpError::Code error) const;

    template <std::size_t ArgumentCount, typename... Args>
    [[nodiscard]] winrt::hstring Format(const ResourceFormatKey<ArgumentCount>& key,
                                        const Args&... args) const
    {
        static_assert(sizeof...(Args) == ArgumentCount);
        const winrt::hstring pattern = Get(ResourceKey{.Name = key.Name});
        return winrt::hstring(
            std::vformat(std::wstring_view(pattern), std::make_wformat_args(args...)));
    }
};

} // namespace tailgate::uwp
