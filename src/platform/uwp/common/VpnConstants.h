#pragma once

#include <cstdint>
#include <string_view>

#include <tailgate/net/Ipv4Address.h>

namespace tailgate::uwp
{

struct VpnConstants final
{
    struct Product final
    {
        static constexpr wchar_t Name[] = L"Tailgate";
        static constexpr wchar_t AdminConsoleUrl[] = L"https://login.tailscale.com/admin/machines";
        static constexpr wchar_t BugReportUrl[] = L"https://github.com/trungnt2910/tailgate/issues";
    };

    struct Channel final
    {
        static constexpr std::uint32_t Mtu = 1280;
        static constexpr std::uint32_t MaximumFrameSize = 1500;
    };

    struct Relay final
    {
        static constexpr std::wstring_view DefaultService = L"443";
    };

    struct Network final
    {
        static constexpr wchar_t ServiceHost[] = L"100.100.100.100";
        static constexpr std::uint32_t ServiceIpv4Address =
            tailgate::net::Ipv4Address::FromOctets(100, 100, 100, 100).HostOrder();
    };

    struct AppService final
    {
        static constexpr std::uint16_t Port = 2910;
    };
};

} // namespace tailgate::uwp
