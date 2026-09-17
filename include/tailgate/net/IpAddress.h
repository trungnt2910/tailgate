#pragma once

#include <array>
#include <compare>
#include <cstdint>
#include <exception>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include <tailgate/net/Ipv4Address.h>

namespace tailgate::net
{

enum class AddressFamily
{
    Ipv4,
    Ipv6,
};

class IpAddressParseError final : public std::exception
{
public:
    [[nodiscard]] const char* what() const noexcept override;
};

class IpAddress final
{
public:
    constexpr IpAddress() noexcept = default;
    explicit IpAddress(Ipv4Address address) noexcept;

    [[nodiscard]] static std::optional<IpAddress> TryParse(std::string_view text);
    [[nodiscard]] static IpAddress Parse(std::string_view text);
    [[nodiscard]] static IpAddress FromIpv6(std::array<std::uint8_t, 16> bytes) noexcept;
    [[nodiscard]] AddressFamily Family() const noexcept;
    [[nodiscard]] std::span<const std::uint8_t> Bytes() const noexcept;
    [[nodiscard]] std::string ToString() const;
    [[nodiscard]] bool IsUnspecified() const noexcept;
    [[nodiscard]] bool operator==(const IpAddress&) const noexcept = default;
    [[nodiscard]] std::strong_ordering operator<=>(const IpAddress&) const noexcept = default;

private:
    AddressFamily m_family = AddressFamily::Ipv4;
    std::array<std::uint8_t, 16> m_bytes{};
};

} // namespace tailgate::net
