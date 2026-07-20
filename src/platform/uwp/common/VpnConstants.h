#pragma once

#include <cstdint>
#include <string_view>

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
        static constexpr std::uint32_t TailnetIpv4Network = (100U << 24U) | (64U << 16U);
        static constexpr std::uint8_t TailnetIpv4PrefixLength = 10;
        static constexpr wchar_t ServiceHost[] = L"100.100.100.100";
        static constexpr std::uint32_t ServiceIpv4Address =
            (100U << 24U) | (100U << 16U) | (100U << 8U) | 100U;
        static constexpr std::uint8_t HostIpv4PrefixLength = 32;
        static constexpr std::uint32_t LowerDefaultIpv4Network = 0;
        static constexpr std::uint32_t UpperDefaultIpv4Network = 128U << 24U;
        static constexpr std::uint8_t SplitDefaultPrefixLength = 1;
    };

    struct AppService final
    {
        static constexpr std::uint16_t Port = 2910;
    };
};

} // namespace tailgate::uwp
