#pragma once

#include <functional>

#include <winrt/Windows.Foundation.h>

namespace tailgate::uwp
{

class Settings final
{
public:
    using Value = winrt::Windows::Foundation::IInspectable;
    using ValueFactory = std::function<Value()>;

    [[nodiscard]] static Value Get(const winrt::hstring& name);
    static void Set(const winrt::hstring& name, const Value& value);
    [[nodiscard]] static Value GetOrCreate(const winrt::hstring& name, const ValueFactory& create);
    [[nodiscard]] static winrt::hstring GetString(const winrt::hstring& name);
    static void SetString(const winrt::hstring& name, const winrt::hstring& value);
    static void Remove(const winrt::hstring& name);
};

} // namespace tailgate::uwp
