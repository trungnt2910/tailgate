#include "tailgate/net/packet/Ip.h"

#include <algorithm>
#include <array>

namespace tailgate::net::packet
{
namespace
{

constexpr std::size_t Ipv4HeaderLength = 20;
constexpr std::size_t Ipv6HeaderLength = 40;
constexpr std::uint8_t HopByHop = 0;
constexpr std::uint8_t Routing = 43;
constexpr std::uint8_t Fragment = 44;
constexpr std::uint8_t DestinationOptions = 60;
constexpr std::size_t MaximumExtensions = 16;

std::uint16_t Read16(std::span<const std::uint8_t> packet, std::size_t offset)
{
    return static_cast<std::uint16_t>((packet[offset] << 8) | packet[offset + 1]);
}

IpAddress ReadAddress(std::span<const std::uint8_t> bytes)
{
    if (bytes.size() == 4)
    {
        return IpAddress(Ipv4Address::FromOctets(bytes[0], bytes[1], bytes[2], bytes[3]));
    }
    std::array<std::uint8_t, 16> address{};
    std::ranges::copy(bytes, address.begin());
    return IpAddress::FromIpv6(address);
}

} // namespace

std::optional<IpEnvelope> ParseIpEnvelope(std::span<const std::uint8_t> packet)
{
    if (packet.empty())
    {
        return std::nullopt;
    }
    IpEnvelope result;
    if ((packet[0] >> 4) == 4)
    {
        if (packet.size() < Ipv4HeaderLength)
        {
            return std::nullopt;
        }
        result.PayloadOffset = (packet[0] & 15U) * 4U;
        if (result.PayloadOffset < Ipv4HeaderLength || result.PayloadOffset > packet.size() ||
            Read16(packet, 2) != packet.size())
        {
            return std::nullopt;
        }
        result.Source = ReadAddress(packet.subspan(12, 4));
        result.Destination = ReadAddress(packet.subspan(16, 4));
        result.Protocol = packet[9];
        constexpr std::uint16_t FragmentOffsetMask = 0x1fff;
        constexpr std::uint16_t MoreFragments = 0x2000;
        const auto flags = Read16(packet, 6);
        result.FirstFragment = (flags & FragmentOffsetMask) == 0;
        result.Fragmented = (flags & (FragmentOffsetMask | MoreFragments)) != 0;
        return result;
    }
    if ((packet[0] >> 4) != 6 || packet.size() < Ipv6HeaderLength ||
        Read16(packet, 4) + Ipv6HeaderLength != packet.size())
    {
        return std::nullopt;
    }
    result.Source = ReadAddress(packet.subspan(8, 16));
    result.Destination = ReadAddress(packet.subspan(24, 16));
    result.Protocol = packet[6];
    result.PayloadOffset = Ipv6HeaderLength;
    std::size_t extensions = 0;
    while (result.Protocol == HopByHop || result.Protocol == Routing ||
           result.Protocol == Fragment || result.Protocol == DestinationOptions)
    {
        if (++extensions > MaximumExtensions || packet.size() - result.PayloadOffset < 8)
        {
            return std::nullopt;
        }
        const auto offset = result.PayloadOffset;
        const bool fragment = result.Protocol == Fragment;
        const auto length = fragment ? 8U : (static_cast<unsigned>(packet[offset + 1]) + 1) * 8U;
        if (length > packet.size() - offset)
        {
            return std::nullopt;
        }
        result.Protocol = packet[offset];
        result.PayloadOffset += length;
        if (fragment)
        {
            result.FragmentProtocol = result.Protocol;
            constexpr std::uint16_t FragmentOffsetMask = 0xfff8;
            constexpr std::uint16_t MoreFragments = 1;
            const auto flags = Read16(packet, offset + 2);
            result.FirstFragment = (flags & FragmentOffsetMask) == 0;
            result.Fragmented = (flags & (FragmentOffsetMask | MoreFragments)) != 0;
            // A noninitial fragment does not contain the following header. Its
            // next-header value still identifies a directly fragmented TCP segment.
            if (!result.FirstFragment)
            {
                return result;
            }
        }
    }
    return result;
}

} // namespace tailgate::net::packet
