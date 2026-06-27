#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tailgate::network
{

struct Ipv4Prefix
{
    std::uint32_t Network = 0;
    std::uint8_t PrefixLength = 0;
};

[[nodiscard]] std::optional<std::uint32_t> ParseIpv4(const std::string& text);
[[nodiscard]] std::string FormatIpv4(std::uint32_t address);
[[nodiscard]] std::optional<Ipv4Prefix> ParseIpv4Prefix(const std::string& text);
[[nodiscard]] bool Contains(const Ipv4Prefix& prefix, std::uint32_t address);
[[nodiscard]] std::uint32_t PrefixMask(std::uint8_t prefixLength);
[[nodiscard]] std::uint16_t InternetChecksum(const std::uint8_t* data, std::size_t size);
[[nodiscard]] std::uint16_t InternetChecksum(const std::vector<std::uint8_t>& data);

[[nodiscard]] std::optional<std::uint32_t> Ipv4Destination(const std::vector<std::uint8_t>& packet);
[[nodiscard]] std::vector<std::uint8_t> BuildUdpPacket(std::uint32_t source,
                                                       std::uint32_t destination,
                                                       std::uint16_t sourcePort,
                                                       std::uint16_t destinationPort,
                                                       const std::vector<std::uint8_t>& payload);
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
ExtractUdpPayload(const std::vector<std::uint8_t>& packet,
                  std::uint32_t source,
                  std::uint32_t destination,
                  std::uint16_t sourcePort,
                  std::uint16_t destinationPort);

} // namespace tailgate::network
