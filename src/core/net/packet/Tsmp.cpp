#include <tailgate/net/packet/Tsmp.h>

#include <algorithm>

#include <tailgate/net/packet/Ipv4.h>

namespace tailgate::net::packet
{
namespace
{

constexpr std::uint8_t TsmpIpProtocol = 99;
constexpr std::uint8_t PingType = 'p';
constexpr std::uint8_t PongType = 'o';
constexpr std::size_t Ipv4MinimumHeaderSize = 20;
constexpr std::size_t Ipv6HeaderSize = 40;
constexpr std::size_t Ipv6PayloadLengthOffset = 4;
constexpr std::size_t Ipv6NextHeaderOffset = 6;
constexpr std::size_t Ipv6HopLimitOffset = 7;
constexpr std::size_t Ipv6SourceOffset = 8;
constexpr std::size_t Ipv6DestinationOffset = 24;
constexpr std::uint8_t Ipv6Version = 6;
constexpr std::uint8_t Ipv6VersionTrafficClass = Ipv6Version << 4U;
constexpr std::uint8_t DefaultHopLimit = 64;
constexpr std::size_t PingPayloadSize = 1 + TsmpToken{}.size();
constexpr std::size_t PongPayloadSize = PingPayloadSize + sizeof(std::uint16_t);
constexpr std::uint8_t Ipv4MoreFragmentsOrOffsetMask = 0x3f;

std::optional<std::size_t> PayloadOffset(const std::vector<std::uint8_t>& packet)
{
    if (packet.size() >= Ipv4MinimumHeaderSize && (packet[0] >> 4U) == 4 &&
        tailgate::net::packet::Ipv4Protocol(packet) == TsmpIpProtocol)
    {
        if ((packet[6] & Ipv4MoreFragmentsOrOffsetMask) != 0 || packet[7] != 0)
        {
            return std::nullopt;
        }
        const std::size_t headerSize = static_cast<std::size_t>(packet[0] & 0x0fU) * 4U;
        return headerSize >= Ipv4MinimumHeaderSize && headerSize <= packet.size()
                   ? std::optional<std::size_t>(headerSize)
                   : std::nullopt;
    }
    if (packet.size() >= Ipv6HeaderSize && (packet[0] >> 4U) == Ipv6Version &&
        packet[Ipv6NextHeaderOffset] == TsmpIpProtocol)
    {
        return Ipv6HeaderSize;
    }
    return std::nullopt;
}

std::vector<std::uint8_t> BuildIpv6Response(const std::vector<std::uint8_t>& request,
                                            const std::vector<std::uint8_t>& payload)
{
    std::vector<std::uint8_t> packet(Ipv6HeaderSize + payload.size());
    packet[0] = Ipv6VersionTrafficClass;
    packet[Ipv6PayloadLengthOffset] = static_cast<std::uint8_t>(payload.size() >> 8U);
    packet[Ipv6PayloadLengthOffset + 1] = static_cast<std::uint8_t>(payload.size());
    packet[Ipv6NextHeaderOffset] = TsmpIpProtocol;
    packet[Ipv6HopLimitOffset] = DefaultHopLimit;
    std::copy_n(request.begin() + Ipv6DestinationOffset, 16, packet.begin() + Ipv6SourceOffset);
    std::copy_n(request.begin() + Ipv6SourceOffset, 16, packet.begin() + Ipv6DestinationOffset);
    std::copy(payload.begin(), payload.end(), packet.begin() + Ipv6HeaderSize);
    return packet;
}

} // namespace

std::vector<std::uint8_t>
BuildTsmpPing(std::uint32_t source, std::uint32_t destination, const TsmpToken& token)
{
    std::vector<std::uint8_t> payload(PingPayloadSize);
    payload[0] = PingType;
    std::copy(token.begin(), token.end(), payload.begin() + 1);
    return tailgate::net::packet::BuildIpv4Packet(source, destination, TsmpIpProtocol, payload);
}

std::optional<std::vector<std::uint8_t>> BuildTsmpPong(const std::vector<std::uint8_t>& packet,
                                                       std::uint16_t peerApiPort)
{
    const std::optional<std::size_t> payloadOffset = PayloadOffset(packet);
    if (!payloadOffset || packet.size() < *payloadOffset + PingPayloadSize ||
        packet[*payloadOffset] != PingType)
    {
        return std::nullopt;
    }
    std::vector<std::uint8_t> payload(PongPayloadSize);
    payload[0] = PongType;
    std::copy_n(packet.begin() + static_cast<std::ptrdiff_t>(*payloadOffset + 1),
                TsmpToken{}.size(),
                payload.begin() + 1);
    payload[PingPayloadSize] = static_cast<std::uint8_t>(peerApiPort >> 8U);
    payload[PingPayloadSize + 1] = static_cast<std::uint8_t>(peerApiPort);
    if ((packet[0] >> 4U) == 4)
    {
        const std::optional<std::uint32_t> source = tailgate::net::packet::Ipv4Source(packet);
        const std::optional<std::uint32_t> destination =
            tailgate::net::packet::Ipv4Destination(packet);
        if (!source || !destination)
        {
            return std::nullopt;
        }
        return tailgate::net::packet::BuildIpv4Packet(
            *destination, *source, TsmpIpProtocol, payload);
    }
    return BuildIpv6Response(packet, payload);
}

std::optional<TsmpPong> ParseTsmpPong(const std::vector<std::uint8_t>& packet)
{
    const std::optional<std::size_t> payloadOffset = PayloadOffset(packet);
    if (!payloadOffset || packet.size() < *payloadOffset + PingPayloadSize ||
        packet[*payloadOffset] != PongType)
    {
        return std::nullopt;
    }
    TsmpPong result;
    std::copy_n(packet.begin() + static_cast<std::ptrdiff_t>(*payloadOffset + 1),
                result.Token.size(),
                result.Token.begin());
    if (packet.size() >= *payloadOffset + PongPayloadSize)
    {
        result.PeerApiPort = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(packet[*payloadOffset + PingPayloadSize]) << 8U) |
            packet[*payloadOffset + PingPayloadSize + 1]);
    }
    return result;
}

} // namespace tailgate::net::packet
