#include "tailgate/net/Endpoint.h"

#include <charconv>
#include <format>
#include <limits>

namespace tailgate::net
{

std::optional<Endpoint> Endpoint::TryParse(std::string_view text) noexcept
{
    const std::size_t separator = text.rfind(':');
    if (separator == std::string_view::npos)
    {
        return std::nullopt;
    }
    const std::optional<Ipv4Address> address = Ipv4Address::TryParse(text.substr(0, separator));
    unsigned int port = 0;
    const std::string_view portText = text.substr(separator + 1);
    const std::from_chars_result parsed =
        std::from_chars(portText.data(), portText.data() + portText.size(), port);
    if (!address || portText.empty() || parsed.ec != std::errc{} ||
        parsed.ptr != portText.data() + portText.size() ||
        port > std::numeric_limits<std::uint16_t>::max())
    {
        return std::nullopt;
    }
    return Endpoint(*address, static_cast<std::uint16_t>(port));
}

Endpoint Endpoint::Parse(std::string_view text)
{
    const std::optional<Endpoint> result = TryParse(text);
    if (!result)
    {
        throw EndpointParseError();
    }
    return *result;
}

std::string Endpoint::ToString() const
{
    return std::format("{}:{}", m_address.ToString(), m_port);
}

} // namespace tailgate::net
