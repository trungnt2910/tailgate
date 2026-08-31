#include "tailgate/net/Ipv4Address.h"

#include <array>
#include <charconv>
#include <format>

namespace tailgate::net
{

std::optional<Ipv4Address> Ipv4Address::TryParse(std::string_view text) noexcept
{
    std::array<std::uint8_t, 4> octets{};
    std::size_t start = 0;
    for (std::size_t index = 0; index < octets.size(); ++index)
    {
        const std::size_t end = text.find('.', start);
        if ((index + 1 < octets.size()) != (end != std::string_view::npos))
        {
            return std::nullopt;
        }
        const std::string_view component = text.substr(start, end - start);
        unsigned int value = 0;
        const std::from_chars_result parsed =
            std::from_chars(component.data(), component.data() + component.size(), value);
        if (component.empty() || parsed.ec != std::errc{} ||
            parsed.ptr != component.data() + component.size() || value > 255)
        {
            return std::nullopt;
        }
        octets[index] = static_cast<std::uint8_t>(value);
        start = end == std::string_view::npos ? text.size() : end + 1;
    }
    return FromOctets(octets[0], octets[1], octets[2], octets[3]);
}

Ipv4Address Ipv4Address::Parse(std::string_view text)
{
    const std::optional<Ipv4Address> result = TryParse(text);
    if (!result)
    {
        throw Ipv4AddressParseError();
    }
    return *result;
}

std::string Ipv4Address::ToString() const
{
    const std::array<std::uint8_t, 4> octets = Octets();
    return std::format("{}.{}.{}.{}", octets[0], octets[1], octets[2], octets[3]);
}

} // namespace tailgate::net
