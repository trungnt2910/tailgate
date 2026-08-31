#pragma once

#include <cstdint>
#include <format>
#include <string>
#include <string_view>

#include <winrt/base.h>

template <>
class std::formatter<winrt::hstring, char> : public std::formatter<std::string_view, char>
{
public:
    template <typename FormatContext>
    auto format(const winrt::hstring& value, FormatContext& context) const
    {
        const std::string utf8 = winrt::to_string(value);
        return std::formatter<std::string_view, char>::format(utf8, context);
    }
};

template <>
class std::formatter<winrt::hresult, char> : public std::formatter<std::int32_t, char>
{
public:
    template <typename FormatContext>
    auto format(winrt::hresult value, FormatContext& context) const
    {
        return std::formatter<std::int32_t, char>::format(value.value, context);
    }
};

template <>
class std::formatter<winrt::guid, char> : public std::formatter<winrt::hstring, char>
{
public:
    template <typename FormatContext>
    auto format(const winrt::guid& value, FormatContext& context) const
    {
        return std::formatter<winrt::hstring, char>::format(winrt::to_hstring(value), context);
    }
};
