#pragma once

#include <cstdint>
#include <format>
#include <string>
#include <string_view>

#include <winrt/base.h>

template <>
struct std::formatter<winrt::hstring, char> : std::formatter<std::string_view, char>
{
    template <typename FormatContext>
    auto format(const winrt::hstring& value, FormatContext& context) const
    {
        const std::string utf8 = winrt::to_string(value);
        return std::formatter<std::string_view, char>::format(utf8, context);
    }
};

template <>
struct std::formatter<winrt::hresult, char> : std::formatter<std::int32_t, char>
{
    template <typename FormatContext>
    auto format(winrt::hresult value, FormatContext& context) const
    {
        return std::formatter<std::int32_t, char>::format(value.value, context);
    }
};

template <>
struct std::formatter<winrt::guid, char> : std::formatter<winrt::hstring, char>
{
    template <typename FormatContext>
    auto format(const winrt::guid& value, FormatContext& context) const
    {
        return std::formatter<winrt::hstring, char>::format(winrt::to_hstring(value), context);
    }
};
