#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace tailgate::net::packet
{

using TsmpToken = std::array<std::uint8_t, 8>;

class TsmpPong
{
public:
    TsmpPong(TsmpToken token, std::uint16_t peerApiPort) noexcept
        : m_token(token), m_peerApiPort(peerApiPort)
    {
    }

    [[nodiscard]] const TsmpToken& Token() const noexcept
    {
        return m_token;
    }

    [[nodiscard]] std::uint16_t PeerApiPort() const noexcept
    {
        return m_peerApiPort;
    }

private:
    TsmpToken m_token{};
    std::uint16_t m_peerApiPort = 0;
};

class TsmpPacket final
{
public:
    [[nodiscard]] static std::vector<std::uint8_t>
    BuildPing(std::uint32_t source, std::uint32_t destination, const TsmpToken& token);
    [[nodiscard]] static std::optional<std::vector<std::uint8_t>>
    BuildPong(const std::vector<std::uint8_t>& packet, std::uint16_t peerApiPort);
    [[nodiscard]] static std::optional<TsmpPong> ParsePong(const std::vector<std::uint8_t>& packet);
};

} // namespace tailgate::net::packet
