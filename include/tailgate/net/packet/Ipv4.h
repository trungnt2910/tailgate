#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tailgate::net::packet
{

struct Ipv4Prefix
{
    std::uint32_t Network = 0;
    std::uint8_t PrefixLength = 0;
};

struct Ipv4UdpDatagram
{
    std::uint32_t Source = 0;
    std::uint32_t Destination = 0;
    std::uint16_t SourcePort = 0;
    std::uint16_t DestinationPort = 0;
    std::vector<std::uint8_t> Payload;
};

[[nodiscard]] std::optional<std::uint32_t> ParseIpv4(const std::string& text);
[[nodiscard]] std::string FormatIpv4(std::uint32_t address);
[[nodiscard]] std::optional<Ipv4Prefix> ParseIpv4Prefix(const std::string& text);
[[nodiscard]] bool Contains(const Ipv4Prefix& prefix, std::uint32_t address);
[[nodiscard]] std::uint32_t PrefixMask(std::uint8_t prefixLength);
[[nodiscard]] std::uint16_t InternetChecksum(const std::uint8_t* data, std::size_t size);
[[nodiscard]] std::uint16_t InternetChecksum(const std::vector<std::uint8_t>& data);

[[nodiscard]] std::optional<std::uint32_t> Ipv4Destination(const std::vector<std::uint8_t>& packet);
[[nodiscard]] std::optional<std::uint32_t> Ipv4Source(const std::vector<std::uint8_t>& packet);
[[nodiscard]] std::uint8_t Ipv4Protocol(const std::vector<std::uint8_t>& packet);
[[nodiscard]] std::vector<std::uint8_t> BuildIpv4Packet(std::uint32_t source,
                                                        std::uint32_t destination,
                                                        std::uint8_t protocol,
                                                        const std::vector<std::uint8_t>& payload);
[[nodiscard]] std::vector<std::uint8_t> BuildUdpPacket(std::uint32_t source,
                                                       std::uint32_t destination,
                                                       std::uint16_t sourcePort,
                                                       std::uint16_t destinationPort,
                                                       const std::vector<std::uint8_t>& payload);
[[nodiscard]] std::optional<Ipv4UdpDatagram>
ParseIpv4UdpDatagram(const std::vector<std::uint8_t>& packet);
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
ExtractUdpPayload(const std::vector<std::uint8_t>& packet,
                  std::uint32_t source,
                  std::uint32_t destination,
                  std::uint16_t sourcePort,
                  std::uint16_t destinationPort);

} // namespace tailgate::net::packet
