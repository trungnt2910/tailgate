#pragma once

#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <string_view>

#include <tailgate/net/Ipv4Address.h>

namespace tailgate::net
{

class EndpointParseError final : public std::exception
{
public:
    [[nodiscard]] const char* what() const noexcept override
    {
        return "invalid IPv4 endpoint";
    }
};

class Endpoint final
{
public:
    constexpr Endpoint() noexcept = default;

    constexpr Endpoint(Ipv4Address address, std::uint16_t port) noexcept
        : m_address(address), m_port(port)
    {
    }

    [[nodiscard]] static std::optional<Endpoint> TryParse(std::string_view text) noexcept;
    [[nodiscard]] static Endpoint Parse(std::string_view text);
    [[nodiscard]] std::string ToString() const;
    [[nodiscard]] bool operator==(const Endpoint&) const = default;

    [[nodiscard]] constexpr Ipv4Address Address() const noexcept
    {
        return m_address;
    }

    [[nodiscard]] constexpr std::uint16_t Port() const noexcept
    {
        return m_port;
    }

private:
    Ipv4Address m_address;
    std::uint16_t m_port = 0;
};

} // namespace tailgate::net
