#pragma once

#include <array>
#include <cstdint>
#include <string>

namespace tailgate::protocol
{

class PublicKey
{
public:
    static constexpr std::size_t Size = 32;

    PublicKey() = default;
    explicit PublicKey(std::array<std::uint8_t, Size> bytes);

    [[nodiscard]] const std::array<std::uint8_t, Size>& Bytes() const;
    [[nodiscard]] std::string ToHex() const;

private:
    std::array<std::uint8_t, Size> m_bytes{};
};

} // namespace tailgate::protocol
