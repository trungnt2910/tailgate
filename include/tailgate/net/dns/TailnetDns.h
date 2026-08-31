#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include <tailgate/net/Ipv4Address.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace tailgate::net::dns
{

inline constexpr std::uint32_t MagicDnsIpv4Address =
    tailgate::net::Ipv4Address::FromOctets(100, 100, 100, 100).HostOrder();
inline constexpr std::uint16_t DnsPort = 53;

class TailnetDnsResponse final
{
public:
    [[nodiscard]] static std::optional<std::vector<std::uint8_t>>
    Build(const tailgate::types::netmap::NetworkConfig& config,
          const std::vector<std::uint8_t>& request);
};

} // namespace tailgate::net::dns
