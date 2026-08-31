#include "app/model/SettingsState.h"

#include <string_view>
#include <utility>

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

UwpDevice::UwpDevice(winrt::hstring group,
                     winrt::hstring name,
                     winrt::hstring address,
                     winrt::hstring ipv6,
                     winrt::hstring operatingSystem,
                     bool online,
                     bool exitNodeOption)
    : m_group(std::move(group)),
      m_name(std::move(name)),
      m_address(std::move(address)),
      m_ipv6(std::move(ipv6)),
      m_operatingSystem(std::move(operatingSystem)),
      m_online(online),
      m_exitNodeOption(exitNodeOption)
{
}

winrt::hstring UwpDevice::MagicDnsName() const
{
    return NormalizeMagicDnsName(m_name);
}

bool UwpDevice::MatchesExitNode(const winrt::hstring& nameOrAddress) const
{
    if (!m_exitNodeOption)
    {
        return false;
    }
    return m_address == nameOrAddress || MagicDnsName() == nameOrAddress ||
           ShortName() == nameOrAddress;
}

const winrt::hstring& UwpDevice::Group() const noexcept
{
    return m_group;
}

const winrt::hstring& UwpDevice::Name() const noexcept
{
    return m_name;
}

const winrt::hstring& UwpDevice::Address() const noexcept
{
    return m_address;
}

const winrt::hstring& UwpDevice::Ipv6() const noexcept
{
    return m_ipv6;
}

const winrt::hstring& UwpDevice::OperatingSystem() const noexcept
{
    return m_operatingSystem;
}

bool UwpDevice::Online() const noexcept
{
    return m_online;
}

bool UwpDevice::ExitNodeOption() const noexcept
{
    return m_exitNodeOption;
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
