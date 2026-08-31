#pragma once

#include <array>
#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <string_view>

namespace tailgate::net
{

class Ipv4AddressParseError final : public std::exception
{
public:
    [[nodiscard]] const char* what() const noexcept override
    {
        return "invalid IPv4 address";
    }
};

class Ipv4Address final
{
private:
    explicit constexpr Ipv4Address(std::uint32_t value) noexcept : m_value(value)
    {
    }

public:
    constexpr Ipv4Address() noexcept = default;

    [[nodiscard]] static constexpr Ipv4Address FromOctets(std::uint8_t first,
                                                          std::uint8_t second,
                                                          std::uint8_t third,
                                                          std::uint8_t fourth) noexcept
    {
        return Ipv4Address((static_cast<std::uint32_t>(first) << 24U) |
                           (static_cast<std::uint32_t>(second) << 16U) |
                           (static_cast<std::uint32_t>(third) << 8U) |
                           static_cast<std::uint32_t>(fourth));
    }

    [[nodiscard]] static constexpr Ipv4Address FromHostOrder(std::uint32_t value) noexcept
    {
        return Ipv4Address(value);
    }

    [[nodiscard]] static std::optional<Ipv4Address> TryParse(std::string_view text) noexcept;
    [[nodiscard]] static Ipv4Address Parse(std::string_view text);

    [[nodiscard]] constexpr std::uint32_t HostOrder() const noexcept
    {
        return m_value;
    }

    [[nodiscard]] constexpr std::array<std::uint8_t, 4> Octets() const noexcept
    {
        return {
            static_cast<std::uint8_t>(m_value >> 24U),
            static_cast<std::uint8_t>(m_value >> 16U),
            static_cast<std::uint8_t>(m_value >> 8U),
            static_cast<std::uint8_t>(m_value),
        };
    }

    [[nodiscard]] std::string ToString() const;

    [[nodiscard]] constexpr bool IsPrivate() const noexcept
    {
        constexpr Ipv4Address ClassAPrivateNetwork = FromOctets(10, 0, 0, 0);
        constexpr Ipv4Address ClassAPrivateMask = FromOctets(255, 0, 0, 0);
        constexpr Ipv4Address ClassBPrivateNetwork = FromOctets(172, 16, 0, 0);
        constexpr Ipv4Address ClassBPrivateMask = FromOctets(255, 240, 0, 0);
        constexpr Ipv4Address ClassCPrivateNetwork = FromOctets(192, 168, 0, 0);
        constexpr Ipv4Address ClassCPrivateMask = FromOctets(255, 255, 0, 0);
        return (m_value & ClassAPrivateMask.HostOrder()) == ClassAPrivateNetwork.HostOrder() ||
               (m_value & ClassBPrivateMask.HostOrder()) == ClassBPrivateNetwork.HostOrder() ||
               (m_value & ClassCPrivateMask.HostOrder()) == ClassCPrivateNetwork.HostOrder();
    }

    [[nodiscard]] constexpr bool operator==(const Ipv4Address&) const noexcept = default;

private:
    std::uint32_t m_value = 0;
};

} // namespace tailgate::net
