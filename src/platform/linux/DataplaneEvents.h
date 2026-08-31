#pragma once

#include <cstdint>

#include <tailgate/base/EventLoop.h>

namespace tailgate::linux_frontend
{

class DataplaneEvent final
{
public:
    enum class Kind : std::uint32_t
    {
        Tun = 1,
        LocalDns,
        Derp,
        UpstreamDns,
        Ping,
        AdvertisedUdp,
        Control,
        RelayControl,
    };

    constexpr DataplaneEvent(Kind kind, std::uint32_t index = 0) noexcept
        : m_kind(kind), m_index(index)
    {
    }

    [[nodiscard]] static DataplaneEvent FromValue(std::uint64_t value) noexcept;
    [[nodiscard]] std::uint64_t Value() const noexcept;
    [[nodiscard]] tailgate::base::EventToken Token() const noexcept;

    [[nodiscard]] constexpr Kind Type() const noexcept
    {
        return m_kind;
    }

    [[nodiscard]] constexpr std::uint32_t Index() const noexcept
    {
        return m_index;
    }

private:
    static constexpr std::uint64_t KindShift = 32;

    Kind m_kind;
    std::uint32_t m_index;
};

} // namespace tailgate::linux_frontend
