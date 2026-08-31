#include "tailgate/net/packet/Ipv4.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <string_view>
#include <utility>

#include <tailgate/net/Ipv4Address.h>

namespace tailgate::net::packet
{

Ipv4UdpDatagram::Ipv4UdpDatagram(std::uint32_t source,
                                 std::uint32_t destination,
                                 std::uint16_t sourcePort,
                                 std::uint16_t destinationPort,
                                 std::vector<std::uint8_t> payload)
    : m_source(source),
      m_destination(destination),
      m_sourcePort(sourcePort),
      m_destinationPort(destinationPort),
      m_payload(std::move(payload))
{
}

namespace
{

constexpr std::size_t Ipv4HeaderSize = 20;
constexpr std::size_t UdpHeaderSize = 8;
constexpr std::size_t Ipv4UdpHeaderSize = Ipv4HeaderSize + UdpHeaderSize;
constexpr std::uint8_t Ipv4Version = 4;
constexpr std::uint8_t UdpProtocol = 17;
constexpr std::uint8_t DefaultTimeToLive = 64;
constexpr std::size_t Ipv4SourceOffset = 12;
constexpr std::size_t Ipv4DestinationOffset = 16;
constexpr std::size_t UdpSourcePortOffset = Ipv4HeaderSize;
constexpr std::size_t UdpDestinationPortOffset = Ipv4HeaderSize + 2;
constexpr std::size_t UdpLengthOffset = Ipv4HeaderSize + 4;

} // namespace

std::uint16_t InternetChecksum(const std::uint8_t* data, std::size_t size)
{
    std::uint32_t sum = 0;
    for (std::size_t index = 0; index < size; index += 2)
    {
        std::uint16_t word = static_cast<std::uint16_t>(data[index]) << 8;
        if (index + 1 < size)
        {
            word |= data[index + 1];
        }
        sum += word;
        sum = (sum & 0xffffU) + (sum >> 16U);
    }
    return static_cast<std::uint16_t>(~sum);
}

std::uint16_t InternetChecksum(const std::vector<std::uint8_t>& data)
{
    return InternetChecksum(data.data(), data.size());
}

std::uint32_t PrefixMask(std::uint8_t prefixLength)
{
    return prefixLength == 0 ? 0 : 0xffffffffU << (32U - prefixLength);
}

std::optional<Ipv4Prefix> Ipv4Prefix::Parse(const std::string& text)
{
    const std::size_t slash = text.find('/');
    const std::optional<tailgate::net::Ipv4Address> address =
        tailgate::net::Ipv4Address::TryParse(text.substr(0, slash));
    if (!address)
    {
        return std::nullopt;
    }
    unsigned length = 32;
    if (slash != std::string::npos)
    {
        const std::string_view lengthText(text.data() + slash + 1, text.size() - slash - 1);
        const auto [end, error] =
            std::from_chars(lengthText.data(), lengthText.data() + lengthText.size(), length);
        if (error != std::errc{} || end != lengthText.data() + lengthText.size())
        {
            return std::nullopt;
        }
    }
    if (length > 32)
    {
        return std::nullopt;
    }
    const auto prefixLength = static_cast<std::uint8_t>(length);
    return Ipv4Prefix(address->HostOrder() & PrefixMask(prefixLength), prefixLength);
}

bool Ipv4Prefix::Contains(std::uint32_t address) const
{
    return (address & PrefixMask(m_prefixLength)) == m_network;
}

std::optional<std::uint32_t> Ipv4Packet::Destination(const std::vector<std::uint8_t>& packet)
{
    if (packet.size() < Ipv4HeaderSize || (packet[0] >> 4U) != Ipv4Version)
    {
        return std::nullopt;
    }
    return (static_cast<std::uint32_t>(packet[Ipv4DestinationOffset]) << 24U) |
           (static_cast<std::uint32_t>(packet[Ipv4DestinationOffset + 1]) << 16U) |
           (static_cast<std::uint32_t>(packet[Ipv4DestinationOffset + 2]) << 8U) |
           packet[Ipv4DestinationOffset + 3];
}

std::optional<std::uint32_t> Ipv4Packet::Source(const std::vector<std::uint8_t>& packet)
{
    if (packet.size() < Ipv4HeaderSize || (packet[0] >> 4U) != Ipv4Version)
    {
        return std::nullopt;
    }
    return (static_cast<std::uint32_t>(packet[Ipv4SourceOffset]) << 24U) |
           (static_cast<std::uint32_t>(packet[Ipv4SourceOffset + 1]) << 16U) |
           (static_cast<std::uint32_t>(packet[Ipv4SourceOffset + 2]) << 8U) |
           packet[Ipv4SourceOffset + 3];
}

std::uint8_t Ipv4Packet::Protocol(const std::vector<std::uint8_t>& packet)
{
    if (packet.size() < Ipv4HeaderSize || (packet[0] >> 4U) != Ipv4Version)
    {
        return 0;
    }
    return packet[9];
}

void WriteIpv4Header(std::vector<std::uint8_t>& packet,
                     std::uint32_t source,
                     std::uint32_t destination,
                     std::uint8_t protocol)
{
    packet[0] = 0x45;
    packet[2] = static_cast<std::uint8_t>(packet.size() >> 8U);
    packet[3] = static_cast<std::uint8_t>(packet.size());
    packet[8] = DefaultTimeToLive;
    packet[9] = protocol;
    for (int index = 0; index < 4; ++index)
    {
        packet[Ipv4SourceOffset + index] = static_cast<std::uint8_t>(source >> (24U - index * 8U));
        packet[Ipv4DestinationOffset + index] =
            static_cast<std::uint8_t>(destination >> (24U - index * 8U));
    }
    const std::uint16_t ipChecksum = InternetChecksum(packet.data(), Ipv4HeaderSize);
    packet[10] = static_cast<std::uint8_t>(ipChecksum >> 8U);
    packet[11] = static_cast<std::uint8_t>(ipChecksum);
}

std::vector<std::uint8_t> Ipv4Packet::Build(std::uint32_t source,
                                            std::uint32_t destination,
                                            std::uint8_t protocol,
                                            const std::vector<std::uint8_t>& payload)
{
    std::vector<std::uint8_t> packet(Ipv4HeaderSize + payload.size());
    WriteIpv4Header(packet, source, destination, protocol);
    std::copy(payload.begin(), payload.end(), packet.begin() + Ipv4HeaderSize);
    return packet;
}

std::vector<std::uint8_t> Ipv4UdpDatagram::Build(std::uint32_t source,
                                                 std::uint32_t destination,
                                                 std::uint16_t sourcePort,
                                                 std::uint16_t destinationPort,
                                                 const std::vector<std::uint8_t>& payload)
{
    const std::size_t udpLength = UdpHeaderSize + payload.size();
    std::vector<std::uint8_t> packet(Ipv4HeaderSize + udpLength);
    WriteIpv4Header(packet, source, destination, UdpProtocol);
    packet[UdpSourcePortOffset] = static_cast<std::uint8_t>(sourcePort >> 8U);
    packet[UdpSourcePortOffset + 1] = static_cast<std::uint8_t>(sourcePort);
    packet[UdpDestinationPortOffset] = static_cast<std::uint8_t>(destinationPort >> 8U);
    packet[UdpDestinationPortOffset + 1] = static_cast<std::uint8_t>(destinationPort);
    packet[UdpLengthOffset] = static_cast<std::uint8_t>(udpLength >> 8U);
    packet[UdpLengthOffset + 1] = static_cast<std::uint8_t>(udpLength);
    std::copy(payload.begin(), payload.end(), packet.begin() + Ipv4UdpHeaderSize);
    return packet;
}

std::optional<Ipv4UdpDatagram> Ipv4UdpDatagram::Parse(const std::vector<std::uint8_t>& packet)
{
    if (packet.size() < Ipv4HeaderSize || (packet[0] >> 4U) != Ipv4Version ||
        packet[9] != UdpProtocol)
    {
        return std::nullopt;
    }
    const std::size_t ipv4HeaderSize = static_cast<std::size_t>(packet[0] & 0x0fU) * 4U;
    if (ipv4HeaderSize < Ipv4HeaderSize || packet.size() < ipv4HeaderSize + UdpHeaderSize)
    {
        return std::nullopt;
    }
    const auto read16 = [&](std::size_t offset)
    {
        return static_cast<std::uint16_t>((static_cast<std::uint16_t>(packet[offset]) << 8U) |
                                          packet[offset + 1]);
    };
    const std::uint16_t udpLength = read16(ipv4HeaderSize + 4);
    if (udpLength < UdpHeaderSize || ipv4HeaderSize + udpLength > packet.size())
    {
        return std::nullopt;
    }
    std::vector<std::uint8_t> payload(
        packet.begin() + static_cast<std::ptrdiff_t>(ipv4HeaderSize + UdpHeaderSize),
        packet.begin() + static_cast<std::ptrdiff_t>(ipv4HeaderSize + udpLength));
    return Ipv4UdpDatagram(*Ipv4Packet::Source(packet),
                           *Ipv4Packet::Destination(packet),
                           read16(ipv4HeaderSize),
                           read16(ipv4HeaderSize + 2),
                           std::move(payload));
}

std::uint32_t Ipv4UdpDatagram::Source() const noexcept
{
    return m_source;
}

std::uint32_t Ipv4UdpDatagram::Destination() const noexcept
{
    return m_destination;
}

std::uint16_t Ipv4UdpDatagram::SourcePort() const noexcept
{
    return m_sourcePort;
}

std::uint16_t Ipv4UdpDatagram::DestinationPort() const noexcept
{
    return m_destinationPort;
}

const std::vector<std::uint8_t>& Ipv4UdpDatagram::Payload() const noexcept
{
    return m_payload;
}

std::optional<std::vector<std::uint8_t>>
Ipv4UdpDatagram::ExtractPayload(const std::vector<std::uint8_t>& packet,
                                std::uint32_t source,
                                std::uint32_t destination,
                                std::uint16_t sourcePort,
                                std::uint16_t destinationPort)
{
    if (packet.size() < Ipv4UdpHeaderSize || packet[9] != UdpProtocol)
    {
        return std::nullopt;
    }
    const auto read32 = [&](std::size_t offset)
    {
        return (static_cast<std::uint32_t>(packet[offset]) << 24U) |
               (static_cast<std::uint32_t>(packet[offset + 1]) << 16U) |
               (static_cast<std::uint32_t>(packet[offset + 2]) << 8U) | packet[offset + 3];
    };
    const auto read16 = [&](std::size_t offset)
    {
        return static_cast<std::uint16_t>((static_cast<std::uint16_t>(packet[offset]) << 8U) |
                                          packet[offset + 1]);
    };
    const std::uint16_t length = read16(UdpLengthOffset);
    if (read32(Ipv4SourceOffset) != source || read32(Ipv4DestinationOffset) != destination ||
        read16(UdpSourcePortOffset) != sourcePort ||
        read16(UdpDestinationPortOffset) != destinationPort || length < UdpHeaderSize ||
        Ipv4HeaderSize + length > packet.size())
    {
        return std::nullopt;
    }
    return std::vector<std::uint8_t>(packet.begin() + Ipv4UdpHeaderSize,
                                     packet.begin() + Ipv4HeaderSize + length);
}

} // namespace tailgate::net::packet
