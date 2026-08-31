#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include <tailgate/crypto/Random.h>
#include <tailgate/net/Endpoint.h>

namespace tailgate::net::stun
{

class TransactionId final
{
public:
    static constexpr std::size_t Size = 12;

    constexpr TransactionId() noexcept = default;

    explicit constexpr TransactionId(std::array<std::uint8_t, Size> value) noexcept : m_value(value)
    {
    }

    [[nodiscard]] static TransactionId Generate(tailgate::crypto::Random& random);
    [[nodiscard]] std::vector<std::uint8_t> BuildBindingRequest() const;
    [[nodiscard]] std::optional<tailgate::net::Endpoint>
    ParseMappedIpv4Endpoint(const std::vector<std::uint8_t>& response) const;

    [[nodiscard]] constexpr auto begin() const noexcept
    {
        return m_value.begin();
    }

    [[nodiscard]] constexpr auto end() const noexcept
    {
        return m_value.end();
    }

    [[nodiscard]] constexpr std::size_t size() const noexcept
    {
        return m_value.size();
    }

    [[nodiscard]] constexpr bool operator==(const TransactionId&) const noexcept = default;

private:
    std::array<std::uint8_t, Size> m_value{};
};

} // namespace tailgate::net::stun
