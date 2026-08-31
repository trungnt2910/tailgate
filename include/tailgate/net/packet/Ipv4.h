#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace tailgate::net::packet
{

class Ipv4Prefix
{
public:
    constexpr Ipv4Prefix() noexcept = default;

    constexpr Ipv4Prefix(std::uint32_t network, std::uint8_t prefixLength) noexcept
        : m_network(network), m_prefixLength(prefixLength)
    {
    }

    [[nodiscard]] static std::optional<Ipv4Prefix> Parse(const std::string& text);
    [[nodiscard]] bool Contains(std::uint32_t address) const;
    [[nodiscard]] bool operator==(const Ipv4Prefix&) const noexcept = default;

    [[nodiscard]] constexpr std::uint32_t Network() const noexcept
    {
        return m_network;
    }

    [[nodiscard]] constexpr std::uint8_t PrefixLength() const noexcept
    {
        return m_prefixLength;
    }

private:
    std::uint32_t m_network = 0;
    std::uint8_t m_prefixLength = 0;
};

class Ipv4Packet final
{
public:
    [[nodiscard]] static std::vector<std::uint8_t> Build(std::uint32_t source,
                                                         std::uint32_t destination,
                                                         std::uint8_t protocol,
                                                         const std::vector<std::uint8_t>& payload);
    [[nodiscard]] static std::optional<std::uint32_t>
    Destination(const std::vector<std::uint8_t>& packet);
    [[nodiscard]] static std::optional<std::uint32_t>
    Source(const std::vector<std::uint8_t>& packet);
    [[nodiscard]] static std::uint8_t Protocol(const std::vector<std::uint8_t>& packet);
};

class Ipv4UdpDatagram
{
public:
    Ipv4UdpDatagram(std::uint32_t source,
                    std::uint32_t destination,
                    std::uint16_t sourcePort,
                    std::uint16_t destinationPort,
                    std::vector<std::uint8_t> payload);

    [[nodiscard]] static std::vector<std::uint8_t> Build(std::uint32_t source,
                                                         std::uint32_t destination,
                                                         std::uint16_t sourcePort,
                                                         std::uint16_t destinationPort,
                                                         const std::vector<std::uint8_t>& payload);
    [[nodiscard]] static std::optional<Ipv4UdpDatagram>
    Parse(const std::vector<std::uint8_t>& packet);
    [[nodiscard]] static std::optional<std::vector<std::uint8_t>>
    ExtractPayload(const std::vector<std::uint8_t>& packet,
                   std::uint32_t source,
                   std::uint32_t destination,
                   std::uint16_t sourcePort,
                   std::uint16_t destinationPort);

    [[nodiscard]] std::uint32_t Source() const noexcept;
    [[nodiscard]] std::uint32_t Destination() const noexcept;
    [[nodiscard]] std::uint16_t SourcePort() const noexcept;
    [[nodiscard]] std::uint16_t DestinationPort() const noexcept;
    [[nodiscard]] const std::vector<std::uint8_t>& Payload() const noexcept;

private:
    std::uint32_t m_source = 0;
    std::uint32_t m_destination = 0;
    std::uint16_t m_sourcePort = 0;
    std::uint16_t m_destinationPort = 0;
    std::vector<std::uint8_t> m_payload;
};

[[nodiscard]] std::uint32_t PrefixMask(std::uint8_t prefixLength);
[[nodiscard]] std::uint16_t InternetChecksum(const std::uint8_t* data, std::size_t size);
[[nodiscard]] std::uint16_t InternetChecksum(const std::vector<std::uint8_t>& data);

} // namespace tailgate::net::packet
