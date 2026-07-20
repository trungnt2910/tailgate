#include "common/Settings.h"

#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Storage.h>

namespace tailgate::uwp
{

namespace storage = winrt::Windows::Storage;

Settings::Value Settings::Get(const winrt::hstring& name)
{
    return storage::ApplicationData::Current().LocalSettings().Values().TryLookup(name);
}

void Settings::Set(const winrt::hstring& name, const Value& value)
{
    storage::ApplicationData::Current().LocalSettings().Values().Insert(name, value);
}

Settings::Value Settings::GetOrCreate(const winrt::hstring& name, const ValueFactory& create)
{
    const auto values = storage::ApplicationData::Current().LocalSettings().Values();
    if (Value existing = values.TryLookup(name))
    {
        return existing;
    }
    Value value = create();
    values.Insert(name, value);
    return value;
}

winrt::hstring Settings::GetString(const winrt::hstring& name)
{
    return winrt::unbox_value_or<winrt::hstring>(Get(name), L"");
}

void Settings::SetString(const winrt::hstring& name, const winrt::hstring& value)
{
    Set(name, winrt::box_value(value));
}

void Settings::Remove(const winrt::hstring& name)
{
    storage::ApplicationData::Current().LocalSettings().Values().Remove(name);
}

} // namespace tailgate::uwp
