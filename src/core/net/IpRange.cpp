#include "tailgate/net/IpRange.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <climits>

namespace tailgate::net
{
namespace
{

IpAddress FromBytes(AddressFamily family, const std::array<std::uint8_t, 16>& bytes)
{
    return family == AddressFamily::Ipv6
               ? IpAddress::FromIpv6(bytes)
               : IpAddress(Ipv4Address::FromOctets(bytes[0], bytes[1], bytes[2], bytes[3]));
}

bool Less(const IpAddress& left, const IpAddress& right)
{
    return std::ranges::lexicographical_compare(left.Bytes(), right.Bytes());
}

} // namespace

IpRange::IpRange(IpAddress first, IpAddress last) noexcept : m_first(first), m_last(last)
{
}

std::optional<IpRange> IpRange::TryParse(std::string_view text)
{
    const auto dash = text.find('-');
    if (dash != std::string_view::npos)
    {
        const auto first = IpAddress::TryParse(text.substr(0, dash));
        const auto last = IpAddress::TryParse(text.substr(dash + 1));
        if (!first || !last || first->Family() != last->Family() || Less(*last, *first))
        {
            return std::nullopt;
        }
        return IpRange(*first, *last);
    }
    const auto slash = text.find('/');
    const auto address = IpAddress::TryParse(text.substr(0, slash));
    if (!address)
    {
        return std::nullopt;
    }
    if (slash == std::string_view::npos)
    {
        return IpRange(*address, *address);
    }
    unsigned prefix = 0;
    const auto suffix = text.substr(slash + 1);
    const auto parsed = std::from_chars(suffix.data(), suffix.data() + suffix.size(), prefix);
    const auto width = static_cast<unsigned>(address->Bytes().size() * CHAR_BIT);
    if (parsed.ec != std::errc{} || parsed.ptr != suffix.data() + suffix.size() || prefix > width)
    {
        return std::nullopt;
    }
    std::array<std::uint8_t, 16> first{};
    std::ranges::copy(address->Bytes(), first.begin());
    auto last = first;
    for (unsigned bit = prefix; bit < width; ++bit)
    {
        const auto mask = static_cast<std::uint8_t>(1U << (CHAR_BIT - 1 - bit % CHAR_BIT));
        first[bit / CHAR_BIT] &= static_cast<std::uint8_t>(~mask);
        last[bit / CHAR_BIT] |= mask;
    }
    return IpRange(FromBytes(address->Family(), first), FromBytes(address->Family(), last));
}

bool IpRange::Contains(const IpAddress& address) const noexcept
{
    return address.Family() == m_first.Family() && !Less(address, m_first) &&
           !Less(m_last, address);
}

} // namespace tailgate::net
