#include "tailgate/protocol/Base64.h"

#include <array>
#include <stdexcept>

namespace tailgate::protocol
{
namespace
{

constexpr char Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::uint8_t DecodeChar(char ch)
{
    if (ch >= 'A' && ch <= 'Z')
    {
        return static_cast<std::uint8_t>(ch - 'A');
    }
    if (ch >= 'a' && ch <= 'z')
    {
        return static_cast<std::uint8_t>(26 + ch - 'a');
    }
    if (ch >= '0' && ch <= '9')
    {
        return static_cast<std::uint8_t>(52 + ch - '0');
    }
    if (ch == '+')
    {
        return 62;
    }
    if (ch == '/')
    {
        return 63;
    }
    throw std::runtime_error("Invalid Base64 character.");
}

} // namespace

std::string Base64Encode(const std::vector<std::uint8_t>& data)
{
    std::string output;
    output.reserve(((data.size() + 2) / 3) * 4);

    for (std::size_t index = 0; index < data.size(); index += 3)
    {
        std::uint32_t value = static_cast<std::uint32_t>(data[index]) << 16;
        bool hasSecond = index + 1 < data.size();
        bool hasThird = index + 2 < data.size();
        if (hasSecond)
        {
            value |= static_cast<std::uint32_t>(data[index + 1]) << 8;
        }
        if (hasThird)
        {
            value |= data[index + 2];
        }

        output.push_back(Alphabet[(value >> 18) & 0x3f]);
        output.push_back(Alphabet[(value >> 12) & 0x3f]);
        output.push_back(hasSecond ? Alphabet[(value >> 6) & 0x3f] : '=');
        output.push_back(hasThird ? Alphabet[value & 0x3f] : '=');
    }

    return output;
}

std::vector<std::uint8_t> Base64Decode(const std::string& text)
{
    if (text.size() % 4 != 0)
    {
        throw std::runtime_error("Base64 length must be a multiple of four.");
    }

    std::vector<std::uint8_t> output;
    output.reserve((text.size() / 4) * 3);

    for (std::size_t index = 0; index < text.size(); index += 4)
    {
        std::uint32_t value = static_cast<std::uint32_t>(DecodeChar(text[index])) << 18;
        value |= static_cast<std::uint32_t>(DecodeChar(text[index + 1])) << 12;
        bool hasThird = text[index + 2] != '=';
        bool hasFourth = text[index + 3] != '=';
        if (hasThird)
        {
            value |= static_cast<std::uint32_t>(DecodeChar(text[index + 2])) << 6;
        }
        if (hasFourth)
        {
            value |= DecodeChar(text[index + 3]);
        }

        output.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
        if (hasThird)
        {
            output.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
        }
        if (hasFourth)
        {
            output.push_back(static_cast<std::uint8_t>(value & 0xff));
        }
    }

    return output;
}

} // namespace tailgate::protocol
