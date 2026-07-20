#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace tailgate::protocol
{

using TsmpToken = std::array<std::uint8_t, 8>;

struct TsmpPong
{
    TsmpToken Token{};
    std::uint16_t PeerApiPort = 0;
};

[[nodiscard]] std::vector<std::uint8_t>
BuildTsmpPing(std::uint32_t source, std::uint32_t destination, const TsmpToken& token);
[[nodiscard]] std::optional<std::vector<std::uint8_t>>
BuildTsmpPong(const std::vector<std::uint8_t>& packet, std::uint16_t peerApiPort);
[[nodiscard]] std::optional<TsmpPong> ParseTsmpPong(const std::vector<std::uint8_t>& packet);

} // namespace tailgate::protocol
