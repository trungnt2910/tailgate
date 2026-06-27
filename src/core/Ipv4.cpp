#include "tailgate/network/Ipv4.h"

#include <algorithm>
#include <array>
#include <stdexcept>

namespace tailgate::network
{
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

std::optional<std::uint32_t> ParseIpv4(const std::string& text)
{
    std::uint32_t result = 0;
    std::size_t start = 0;
    for (int component = 0; component < 4; ++component)
    {
        const std::size_t end = text.find('.', start);
        if ((component < 3) != (end != std::string::npos))
        {
            return std::nullopt;
        }
        const std::string part = text.substr(start, end - start);
        if (part.empty() || part.size() > 3)
        {
            return std::nullopt;
        }
        int value = 0;
        for (char character : part)
        {
            if (character < '0' || character > '9')
            {
                return std::nullopt;
            }
            value = value * 10 + character - '0';
        }
        if (value > 255)
        {
            return std::nullopt;
        }
        result = (result << 8U) | static_cast<std::uint32_t>(value);
        start = end == std::string::npos ? text.size() : end + 1;
    }
    return result;
}

std::string FormatIpv4(std::uint32_t address)
{
    return std::to_string((address >> 24U) & 0xffU) + "." +
           std::to_string((address >> 16U) & 0xffU) + "." +
           std::to_string((address >> 8U) & 0xffU) + "." + std::to_string(address & 0xffU);
}

std::uint32_t PrefixMask(std::uint8_t prefixLength)
{
    return prefixLength == 0 ? 0 : 0xffffffffU << (32U - prefixLength);
}

std::optional<Ipv4Prefix> ParseIpv4Prefix(const std::string& text)
{
    const std::size_t slash = text.find('/');
    const std::optional<std::uint32_t> address = ParseIpv4(text.substr(0, slash));
    if (!address)
    {
        return std::nullopt;
    }
    int length = 32;
    try
    {
        length = slash == std::string::npos ? 32 : std::stoi(text.substr(slash + 1));
    }
    catch (const std::exception&)
    {
        return std::nullopt;
    }
    if (length < 0 || length > 32)
    {
        return std::nullopt;
    }
    const auto prefixLength = static_cast<std::uint8_t>(length);
    return Ipv4Prefix{*address & PrefixMask(prefixLength), prefixLength};
}

bool Contains(const Ipv4Prefix& prefix, std::uint32_t address)
{
    return (address & PrefixMask(prefix.PrefixLength)) == prefix.Network;
}

std::optional<std::uint32_t> Ipv4Destination(const std::vector<std::uint8_t>& packet)
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

std::vector<std::uint8_t> BuildUdpPacket(std::uint32_t source,
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

std::optional<std::vector<std::uint8_t>> ExtractUdpPayload(const std::vector<std::uint8_t>& packet,
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

} // namespace tailgate::network
