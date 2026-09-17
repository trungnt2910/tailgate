#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

#include <tailgate/net/IpAddress.h>

namespace tailgate::net::packet
{

// Routing/authentication envelope only. Transport validation and reassembly
// remain the receiving TCP/IP stack's responsibility.
struct IpEnvelope
{
    IpAddress Source;
    IpAddress Destination;
    std::uint8_t Protocol = 0;
    std::size_t PayloadOffset = 0;
    bool Fragmented = false;
    bool FirstFragment = true;
    // IPv6 next-header value immediately after the fragment header, shared by
    // every fragment even when only the first can expose the final transport.
    std::optional<std::uint8_t> FragmentProtocol;
};

[[nodiscard]] std::optional<IpEnvelope> ParseIpEnvelope(std::span<const std::uint8_t> packet);

} // namespace tailgate::net::packet
