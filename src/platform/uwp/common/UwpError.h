#pragma once

#include <cstdint>
#include <optional>

#include <winerror.h>

#include <winrt/base.h>

namespace tailgate::uwp
{

struct ResourceKey;

class UwpError final
{
public:
    UwpError() = delete;

    enum Code : std::uint32_t
    {
        None = 0,
        Unexpected = 1,
        RelayConnectionFailed = 2,
        ConnectionCancelled = 3,
        VpnServerRequired = 4,
        VpnServerInvalid = 5,
        VpnProfileTransitionTimedOut = 6,
        VpnProfileOperationFailed = 7,
        VpnProfileDidNotConnect = 8,
        VpnDisconnectFailed = 9,
        VpnLogoutFailed = 10,
        PreviousConnectionRestoreFailed = 11,
        DeviceApprovalRequired = 12,
        DeviceAuthorizationRequired = 13,
        VpnAddressUnavailable = 14,
        VpnBackgroundRestartTimedOut = 15,
        ExitNodeRejected = 16,
        ExitNodeFailed = 17,
    };

    [[nodiscard]] static constexpr bool IsValid(Code code) noexcept
    {
        return code > Code::None && code <= Code::ExitNodeFailed;
    }

    [[nodiscard]] static const ResourceKey& Resource(Code error) noexcept;

    [[nodiscard]] static constexpr winrt::hresult ToHresult(Code code) noexcept
    {
        return winrt::hresult{
            static_cast<std::int32_t>(HresultBase | static_cast<std::uint32_t>(code))};
    }

    [[nodiscard]] static std::optional<Code> FromHresult(winrt::hresult value) noexcept
    {
        const auto raw = static_cast<std::uint32_t>(value);
        if ((raw & HresultMask) != HresultBase)
        {
            return std::nullopt;
        }
        const auto code = static_cast<Code>(raw & ValueMask);
        return IsValid(code) ? std::optional(code) : std::nullopt;
    }

    [[noreturn]] static void Throw(Code code)
    {
        winrt::throw_hresult(ToHresult(code));
    }

private:
    // FACILITY_ITF codes 0x0200-0xFFFF are developer-defined. Tailgate owns
    // 0xA000-0xA0FF within its internal UWP controller boundary.
    inline static constexpr std::uint32_t CodeBase = 0x0000A000U;
    inline static constexpr std::uint32_t HresultBase =
        (static_cast<std::uint32_t>(SEVERITY_ERROR) << 31U) |
        (static_cast<std::uint32_t>(FACILITY_ITF) << 16U) | CodeBase;
    inline static constexpr std::uint32_t ValueMask = 0x000000FFU;
    inline static constexpr std::uint32_t HresultMask = ~ValueMask;
    static_assert(static_cast<std::uint32_t>(Code::ExitNodeFailed) <= ValueMask);
};

} // namespace tailgate::uwp
