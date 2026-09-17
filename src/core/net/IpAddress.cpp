#include "tailgate/net/IpAddress.h"

#include <algorithm>
#include <array>
#include <cstring>

#include <lwip/ip6_addr.h>

namespace tailgate::net
{

const char* IpAddressParseError::what() const noexcept
{
    return "invalid IP address";
}

IpAddress::IpAddress(Ipv4Address address) noexcept
{
    const auto bytes = address.Octets();
    std::ranges::copy(bytes, m_bytes.begin());
}

std::optional<IpAddress> IpAddress::TryParse(std::string_view text)
{
    if (const auto address = Ipv4Address::TryParse(text))
    {
        return IpAddress(*address);
    }
    // A tailnet address is unscoped. Never let a C parser accept only the prefix before a NUL.
    if (text.find(':') == std::string_view::npos ||
        text.find_first_not_of("0123456789abcdefABCDEF:.") != std::string_view::npos)
    {
        return std::nullopt;
    }
    ip6_addr_t address{};
    if (ip6addr_aton(std::string(text).c_str(), &address) == 0)
    {
        return std::nullopt;
    }
    std::array<std::uint8_t, 16> bytes{};
    std::memcpy(bytes.data(), address.addr, bytes.size());
    return FromIpv6(bytes);
}

IpAddress IpAddress::Parse(std::string_view text)
{
    const auto address = TryParse(text);
    if (!address)
    {
        throw IpAddressParseError();
    }
    return *address;
}

IpAddress IpAddress::FromIpv6(std::array<std::uint8_t, 16> bytes) noexcept
{
    IpAddress result;
    result.m_family = AddressFamily::Ipv6;
    result.m_bytes = bytes;
    return result;
}

AddressFamily IpAddress::Family() const noexcept
{
    return m_family;
}

std::span<const std::uint8_t> IpAddress::Bytes() const noexcept
{
    constexpr std::size_t Ipv4Size = 4;
    return std::span(m_bytes).first(m_family == AddressFamily::Ipv4 ? Ipv4Size : m_bytes.size());
}

std::string IpAddress::ToString() const
{
    if (m_family == AddressFamily::Ipv4)
    {
        return Ipv4Address::FromOctets(m_bytes[0], m_bytes[1], m_bytes[2], m_bytes[3]).ToString();
    }
    ip6_addr_t address{};
    std::memcpy(address.addr, m_bytes.data(), m_bytes.size());
    std::array<char, IP6ADDR_STRLEN_MAX> text{};
    (void)ip6addr_ntoa_r(&address, text.data(), static_cast<int>(text.size()));
    return text.data();
}

bool IpAddress::IsUnspecified() const noexcept
{
    return std::ranges::all_of(m_bytes,
                               [](std::uint8_t byte)
                               {
                                   return byte == 0;
                               });
}

} // namespace tailgate::net
