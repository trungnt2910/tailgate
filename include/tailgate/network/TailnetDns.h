#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include <tailgate/control/NetworkMap.h>

namespace tailgate::network
{

inline constexpr std::uint32_t MagicDnsIpv4Address = 0x64646464U;
inline constexpr std::uint16_t DnsPort = 53;

[[nodiscard]] std::optional<std::vector<std::uint8_t>>
BuildTailnetDnsResponse(const control::NetworkConfig& config,
                        const std::vector<std::uint8_t>& request);

} // namespace tailgate::network
