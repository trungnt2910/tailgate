#include "tailgate/network/Dns.h"

#include <algorithm>
#include <cctype>

namespace tailgate::network
{

std::optional<std::string> DnsQueryName(const std::vector<std::uint8_t>& message)
{
    constexpr std::size_t dnsHeaderSize = 12;
    constexpr std::size_t questionFooterSize = 4;
    constexpr std::size_t maximumLabelLength = 63;
    if (message.size() < dnsHeaderSize ||
        ((static_cast<std::uint16_t>(message[4]) << 8U) | message[5]) == 0)
    {
        return std::nullopt;
    }
    std::string result;
    std::size_t offset = dnsHeaderSize;
    while (offset < message.size() && message[offset] != 0)
    {
        const std::size_t length = message[offset++];
        if (length > maximumLabelLength || offset + length > message.size())
        {
            return std::nullopt;
        }
        if (!result.empty())
        {
            result.push_back('.');
        }
        result.append(message.begin() + static_cast<std::ptrdiff_t>(offset),
                      message.begin() + static_cast<std::ptrdiff_t>(offset + length));
        offset += length;
    }
    if (offset >= message.size() || offset + 1 + questionFooterSize > message.size())
    {
        return std::nullopt;
    }
    std::transform(result.begin(),
                   result.end(),
                   result.begin(),
                   [](unsigned char value)
                   {
                       return static_cast<char>(std::tolower(value));
                   });
    return result;
}

bool DnsNameHasSuffix(const std::string& name, const std::string& suffix)
{
    std::string normalized = suffix;
    if (!normalized.empty() && normalized.back() == '.')
    {
        normalized.pop_back();
    }
    if (name == normalized)
    {
        return true;
    }
    return name.size() > normalized.size() &&
           name.compare(name.size() - normalized.size(), normalized.size(), normalized) == 0 &&
           name[name.size() - normalized.size() - 1] == '.';
}

} // namespace tailgate::network
