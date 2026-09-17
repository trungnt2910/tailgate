#pragma once

#include <algorithm>
#include <span>
#include <vector>

#include <tailgate/net/IpAddress.h>
#include <tailgate/net/packet/Ipv4.h>

namespace tailgate::tests::fakes
{

inline void PutNetwork16(std::vector<std::uint8_t>& packet, std::size_t offset, std::size_t value)
{
    packet[offset] = static_cast<std::uint8_t>(value >> 8);
    packet[offset + 1] = static_cast<std::uint8_t>(value);
}

inline std::vector<std::vector<std::uint8_t>> FragmentIpv4(std::span<const std::uint8_t> packet)
{
    constexpr std::size_t HeaderLength = 20;
    constexpr std::size_t FragmentPayloadLength = 32;
    constexpr std::uint16_t MoreFragments = 0x2000;
    std::vector<std::vector<std::uint8_t>> result;
    const auto payload = packet.subspan(HeaderLength);
    for (std::size_t offset = 0; offset < payload.size(); offset += FragmentPayloadLength)
    {
        const auto size = std::min(FragmentPayloadLength, payload.size() - offset);
        const bool more = offset + size != payload.size();
        std::vector<std::uint8_t> fragment(packet.begin(), packet.begin() + HeaderLength);
        fragment.insert(fragment.end(), payload.begin() + offset, payload.begin() + offset + size);
        PutNetwork16(fragment, 2, fragment.size());
        PutNetwork16(fragment, 6, (offset / 8) | (more ? MoreFragments : 0));
        PutNetwork16(fragment, 10, 0);
        PutNetwork16(fragment, 10, net::packet::InternetChecksum(fragment.data(), HeaderLength));
        result.push_back(std::move(fragment));
    }
    return result;
}

inline std::vector<std::vector<std::uint8_t>> FragmentIpv6(std::span<const std::uint8_t> packet)
{
    constexpr std::size_t HeaderLength = 40;
    constexpr std::size_t FragmentHeaderLength = 8;
    constexpr std::size_t FragmentPayloadLength = 32;
    constexpr std::uint8_t FragmentProtocol = 44;
    std::vector<std::vector<std::uint8_t>> result;
    const auto payload = packet.subspan(HeaderLength);
    for (std::size_t offset = 0; offset < payload.size(); offset += FragmentPayloadLength)
    {
        const auto size = std::min(FragmentPayloadLength, payload.size() - offset);
        const bool more = offset + size != payload.size();
        std::vector<std::uint8_t> fragment(packet.begin(), packet.begin() + HeaderLength);
        fragment.resize(HeaderLength + FragmentHeaderLength);
        fragment[6] = FragmentProtocol;
        fragment[HeaderLength] = packet[6];
        fragment[HeaderLength + 7] = 1; // Test datagram identifier.
        PutNetwork16(fragment, HeaderLength + 2, offset | (more ? 1 : 0));
        fragment.insert(fragment.end(), payload.begin() + offset, payload.begin() + offset + size);
        PutNetwork16(fragment, 4, FragmentHeaderLength + size);
        result.push_back(std::move(fragment));
    }
    return result;
}

inline void AddIpv6DestinationOptions(std::vector<std::uint8_t>& packet)
{
    constexpr std::size_t HeaderLength = 40;
    constexpr std::size_t ExtensionLength = 8;
    constexpr std::uint8_t DestinationOptionsProtocol = 60;
    const auto originalProtocol = packet[6];
    packet.insert(packet.begin() + HeaderLength, ExtensionLength, 0);
    packet[6] = DestinationOptionsProtocol;
    packet[HeaderLength] = originalProtocol;
    PutNetwork16(packet, 4, packet.size() - HeaderLength);
}

inline std::vector<std::uint8_t> Ipv6UdpWithDestinationOptions(const net::IpAddress& source,
                                                               const net::IpAddress& destination)
{
    constexpr std::size_t HeaderLength = 40;
    constexpr std::uint8_t UdpProtocol = 17;
    std::vector<std::uint8_t> packet(HeaderLength + 64);
    packet[0] = 0x60;
    packet[6] = UdpProtocol;
    packet[7] = 64;
    std::ranges::copy(source.Bytes(), packet.begin() + 8);
    std::ranges::copy(destination.Bytes(), packet.begin() + 24);
    PutNetwork16(packet, 4, packet.size() - HeaderLength);
    // Only IP reassembly/demux is under test; the receiving UDP stack, not the
    // raw callback, owns validation of the intentionally opaque UDP payload.
    AddIpv6DestinationOptions(packet);
    return packet;
}

} // namespace tailgate::tests::fakes
