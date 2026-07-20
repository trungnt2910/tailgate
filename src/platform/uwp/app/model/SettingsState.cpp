#include "app/model/SettingsState.h"

#include <string_view>

#include <winrt/Windows.Foundation.h>

namespace tailgate::uwp
{

namespace
{

winrt::hstring NormalizeMagicDnsName(const winrt::hstring& name)
{
    const std::wstring_view view(name);
    return view.ends_with(L".") ? winrt::hstring(view.substr(0, view.size() - 1)) : name;
}

winrt::hstring ExtractShortName(const winrt::hstring& name)
{
    const std::wstring_view view(name);
    const std::size_t dot = view.find(L'.');
    return dot == std::wstring_view::npos ? name : winrt::hstring(view.substr(0, dot));
}

} // namespace

winrt::hstring UwpDevice::MagicDnsName() const
{
    return NormalizeMagicDnsName(Name);
}

bool UwpDevice::MatchesExitNode(const winrt::hstring& nameOrAddress) const
{
    if (!ExitNodeOption)
    {
        return false;
    }
    return Address == nameOrAddress || MagicDnsName() == nameOrAddress ||
           ShortName() == nameOrAddress;
}

winrt::hstring UwpDevice::ShortName() const
{
    return ExtractShortName(MagicDnsName());
}

winrt::hstring SettingsState::AccountTitle() const
{
    return AccountName();
}

winrt::hstring SettingsState::TailgateHostPort() const
{
    try
    {
        const winrt::Windows::Foundation::Uri uri(TailgateServer());
        return uri.Host() + L":" + winrt::to_hstring(uri.Port());
    }
    catch (const winrt::hresult_error&)
    {
        return TailgateServer();
    }
}

winrt::hstring SettingsState::TailnetTitle() const
{
    if (!TailnetDisplayName().empty())
    {
        return TailnetDisplayName();
    }
    return TailnetName();
}

} // namespace tailgate::uwp
