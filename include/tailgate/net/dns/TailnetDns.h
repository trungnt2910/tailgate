#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::net::dns
{

inline constexpr std::uint32_t MagicDnsIpv4Address = 0x64646464U;
inline constexpr std::uint16_t DnsPort = 53;

[[nodiscard]] std::optional<std::vector<std::uint8_t>>
BuildTailnetDnsResponse(const tailgate::types::netmap::NetworkConfig& config,
                        const std::vector<std::uint8_t>& request);

} // namespace tailgate::net::dns
