#include <tailgate/net/stun/Stun.h>

#include <algorithm>
#include <cstddef>
#include <format>

#include <tailgate/net/packet/Ipv4.h>

namespace tailgate::net::stun
{
namespace
{

constexpr std::uint16_t BindingRequest = 0x0001;
constexpr std::uint16_t BindingSuccessResponse = 0x0101;
constexpr std::uint16_t SoftwareAttribute = 0x8022;
constexpr std::uint16_t FingerprintAttribute = 0x8028;
constexpr std::uint16_t XorMappedAddressAttribute = 0x0020;
constexpr std::uint16_t AlternateXorMappedAddressAttribute = 0x8020;
constexpr std::uint32_t MagicCookie = 0x2112A442;
constexpr std::uint32_t FingerprintXor = 0x5354554e;
constexpr std::size_t HeaderSize = 20;
constexpr std::size_t Ipv4XorMappedAddressSize = 8;
constexpr char Software[] = "tailnode";

void Write16(std::vector<std::uint8_t>& output, std::uint16_t value)
{
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

void Write32(std::vector<std::uint8_t>& output, std::uint32_t value)
{
    output.push_back(static_cast<std::uint8_t>(value >> 24U));
    output.push_back(static_cast<std::uint8_t>(value >> 16U));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

std::uint16_t Read16(const std::vector<std::uint8_t>& input, std::size_t offset)
{
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(input[offset]) << 8U) |
                                      input[offset + 1]);
}

std::uint32_t Read32(const std::vector<std::uint8_t>& input, std::size_t offset)
{
    return (static_cast<std::uint32_t>(input[offset]) << 24U) |
           (static_cast<std::uint32_t>(input[offset + 1]) << 16U) |
           (static_cast<std::uint32_t>(input[offset + 2]) << 8U) | input[offset + 3];
}

std::uint32_t Crc32(const std::vector<std::uint8_t>& input)
{
    std::uint32_t crc = 0xffffffffU;
    for (const std::uint8_t byte : input)
    {
        crc ^= byte;
        for (int bit = 0; bit < 8; ++bit)
        {
            const std::uint32_t mask = 0U - (crc & 1U);
            crc = (crc >> 1U) ^ (0xedb88320U & mask);
        }
    }
    return ~crc;
}

} // namespace

std::vector<std::uint8_t> BuildBindingRequest(const TransactionId& transactionId)
{
    constexpr std::uint16_t SoftwareLength = sizeof(Software) - 1;
    constexpr std::uint16_t AttributeLength = 4 + SoftwareLength + 8;
    std::vector<std::uint8_t> request;
    request.reserve(HeaderSize + AttributeLength);
    Write16(request, BindingRequest);
    Write16(request, AttributeLength);
    Write32(request, MagicCookie);
    request.insert(request.end(), transactionId.begin(), transactionId.end());
    Write16(request, SoftwareAttribute);
    Write16(request, SoftwareLength);
    request.insert(request.end(), Software, Software + SoftwareLength);
    Write16(request, FingerprintAttribute);
    Write16(request, 4);
    Write32(request, Crc32(request) ^ FingerprintXor);
    return request;
}

std::optional<std::string> ParseMappedIpv4Endpoint(const std::vector<std::uint8_t>& response,
                                                   const TransactionId& transactionId)
{
    if (response.size() < HeaderSize || Read16(response, 0) != BindingSuccessResponse ||
        Read32(response, 4) != MagicCookie ||
        !std::equal(transactionId.begin(), transactionId.end(), response.begin() + 8))
    {
        return std::nullopt;
    }
    const std::size_t messageLength = Read16(response, 2);
    if (HeaderSize + messageLength > response.size())
    {
        return std::nullopt;
    }
    std::size_t offset = HeaderSize;
    while (offset + 4 <= HeaderSize + messageLength)
    {
        const std::uint16_t type = Read16(response, offset);
        const std::uint16_t length = Read16(response, offset + 2);
        offset += 4;
        if (offset + length > response.size())
        {
            return std::nullopt;
        }
        if ((type == XorMappedAddressAttribute || type == AlternateXorMappedAddressAttribute) &&
            length >= Ipv4XorMappedAddressSize && response[offset + 1] == 0x01)
        {
            const std::uint16_t port =
                static_cast<std::uint16_t>(Read16(response, offset + 2) ^ (MagicCookie >> 16U));
            const std::uint32_t address = Read32(response, offset + 4) ^ MagicCookie;
            return std::format("{}:{}", tailgate::net::packet::FormatIpv4(address), port);
        }
        offset += (static_cast<std::size_t>(length) + 3U) & ~std::size_t{3U};
    }
    return std::nullopt;
}

} // namespace tailgate::net::stun
