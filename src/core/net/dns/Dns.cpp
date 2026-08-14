#include <tailgate/net/dns/Dns.h>

#include <format>
#include <stdexcept>
#include <utility>

#include <boost/algorithm/string/case_conv.hpp>

namespace tailgate::net::dns
{
namespace
{

constexpr std::size_t DnsHeaderSize = 12;
constexpr std::size_t MaximumDnsNameDepth = 32;
constexpr std::uint8_t DnsResponseFlag = 0x80;
constexpr std::uint8_t DnsResponseCodeMask = 0x0f;
constexpr std::uint16_t DnsTypeA = 1;
constexpr std::uint16_t DnsTypeCname = 5;
constexpr std::uint16_t DnsTypeDname = 39;

const char* DnsResponseCodeName(std::uint8_t code)
{
    switch (code)
    {
    case 0:
        return "NOERROR";
    case 1:
        return "FORMERR";
    case 2:
        return "SERVFAIL";
    case 3:
        return "NXDOMAIN";
    case 4:
        return "NOTIMP";
    case 5:
        return "REFUSED";
    default:
        return "unknown";
    }
}

std::uint16_t Read16(const std::vector<std::uint8_t>& message, std::size_t offset)
{
    if (offset + 2 > message.size())
    {
        throw std::runtime_error("Truncated DNS message.");
    }
    return (static_cast<std::uint16_t>(message[offset]) << 8U) | message[offset + 1];
}

std::string
ReadName(const std::vector<std::uint8_t>& message, std::size_t& offset, std::size_t depth = 0)
{
    if (depth >= MaximumDnsNameDepth)
    {
        throw std::runtime_error("DNS name compression loop.");
    }
    std::string result;
    while (offset < message.size())
    {
        const std::uint8_t length = message[offset++];
        if (length == 0)
        {
            return result;
        }
        if ((length & 0xc0U) == 0xc0U)
        {
            if (offset >= message.size())
            {
                throw std::runtime_error("Truncated DNS name pointer.");
            }
            std::size_t pointer =
                (static_cast<std::size_t>(length & 0x3fU) << 8U) | message[offset++];
            const std::string suffix = ReadName(message, pointer, depth + 1);
            if (!result.empty() && !suffix.empty())
            {
                result.push_back('.');
            }
            return result + suffix;
        }
        if ((length & 0xc0U) != 0 || length > 63 || offset + length > message.size())
        {
            throw std::runtime_error("Invalid DNS label.");
        }
        if (!result.empty())
        {
            result.push_back('.');
        }
        result.append(message.begin() + static_cast<std::ptrdiff_t>(offset),
                      message.begin() + static_cast<std::ptrdiff_t>(offset + length));
        offset += length;
    }
    throw std::runtime_error("Unterminated DNS name.");
}

std::string NormalizeName(std::string value)
{
    if (!value.empty() && value.back() == '.')
    {
        value.pop_back();
    }
    boost::algorithm::to_lower(value);
    return value;
}

struct ResourceRecord
{
    std::string Name;
    std::uint16_t Type = 0;
    std::string NameValue;
    std::string Address;
};

} // namespace

DnsResponseError::DnsResponseError(std::string queriedName, std::uint8_t responseCode)
    : std::runtime_error(std::format(
          "DNS lookup failed for {}: {}.", queriedName, DnsResponseCodeName(responseCode))),
      m_queriedName(std::move(queriedName)),
      m_responseCode(responseCode)
{
}

const std::string& DnsResponseError::QueriedName() const noexcept
{
    return m_queriedName;
}

std::uint8_t DnsResponseError::ResponseCode() const noexcept
{
    return m_responseCode;
}

std::optional<std::string> DnsQueryName(const std::vector<std::uint8_t>& message)
{
    constexpr std::size_t dnsHeaderSize = DnsHeaderSize;
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
    boost::algorithm::to_lower(result);
    return result;
}

std::vector<std::uint8_t> BuildDnsQuery(const std::string& name, std::uint16_t transactionId)
{
    std::vector<std::uint8_t> result(DnsHeaderSize, 0);
    result[0] = static_cast<std::uint8_t>(transactionId >> 8U);
    result[1] = static_cast<std::uint8_t>(transactionId);
    result[2] = 1;
    result[5] = 1;
    std::size_t start = 0;
    const std::string normalized = NormalizeName(name);
    while (start < normalized.size())
    {
        const std::size_t dot = normalized.find('.', start);
        const std::size_t end = dot == std::string::npos ? normalized.size() : dot;
        const std::size_t length = end - start;
        if (length == 0 || length > 63)
        {
            throw std::invalid_argument("Invalid DNS query name.");
        }
        result.push_back(static_cast<std::uint8_t>(length));
        result.insert(result.end(),
                      normalized.begin() + static_cast<std::ptrdiff_t>(start),
                      normalized.begin() + static_cast<std::ptrdiff_t>(end));
        start = end + 1;
    }
    result.insert(result.end(), {0, 0, static_cast<std::uint8_t>(DnsTypeA), 0, 1});
    return result;
}

DnsAnswer ParseDnsAnswer(const std::vector<std::uint8_t>& message,
                         std::uint16_t transactionId,
                         const std::string& queriedName)
{
    if (message.size() < DnsHeaderSize || Read16(message, 0) != transactionId)
    {
        throw std::runtime_error("DNS response transaction does not match.");
    }
    if ((message[2] & DnsResponseFlag) == 0)
    {
        throw std::runtime_error(
            std::format("DNS query for {} returned a message without the response flag.",
                        NormalizeName(queriedName)));
    }
    const std::uint8_t responseCode = message[3] & DnsResponseCodeMask;
    if (responseCode != 0)
    {
        throw DnsResponseError(NormalizeName(queriedName), responseCode);
    }
    const std::uint16_t questionCount = Read16(message, 4);
    const std::uint16_t answerCount = Read16(message, 6);
    std::size_t offset = DnsHeaderSize;
    for (std::uint16_t index = 0; index < questionCount; ++index)
    {
        (void)ReadName(message, offset);
        if (offset + 4 > message.size())
        {
            throw std::runtime_error("Truncated DNS question.");
        }
        offset += 4;
    }
    std::vector<ResourceRecord> records;
    for (std::uint16_t index = 0; index < answerCount; ++index)
    {
        ResourceRecord record;
        record.Name = NormalizeName(ReadName(message, offset));
        if (offset + 10 > message.size())
        {
            throw std::runtime_error("Truncated DNS answer.");
        }
        record.Type = Read16(message, offset);
        const std::uint16_t length = Read16(message, offset + 8);
        offset += 10;
        const std::size_t dataOffset = offset;
        if (offset + length > message.size())
        {
            throw std::runtime_error("Truncated DNS answer data.");
        }
        if ((record.Type == DnsTypeCname || record.Type == DnsTypeDname) && length != 0)
        {
            record.NameValue = NormalizeName(ReadName(message, offset));
        }
        else if (record.Type == DnsTypeA && length == 4)
        {
            record.Address = std::format("{}.{}.{}.{}",
                                         message[offset],
                                         message[offset + 1],
                                         message[offset + 2],
                                         message[offset + 3]);
        }
        offset = dataOffset + length;
        records.push_back(std::move(record));
    }
    DnsAnswer result;
    result.CanonicalName = NormalizeName(queriedName);
    for (std::size_t pass = 0; pass < records.size(); ++pass)
    {
        bool changed = false;
        for (const ResourceRecord& record : records)
        {
            if (record.Type == DnsTypeCname && record.Name == result.CanonicalName)
            {
                result.CanonicalName = record.NameValue;
                changed = true;
                break;
            }
            if (record.Type == DnsTypeDname && DnsNameHasSuffix(result.CanonicalName, record.Name))
            {
                const std::size_t prefixLength = result.CanonicalName.size() - record.Name.size();
                result.CanonicalName =
                    result.CanonicalName.substr(0, prefixLength) + record.NameValue;
                changed = true;
                break;
            }
        }
        if (!changed)
        {
            break;
        }
    }
    for (const ResourceRecord& record : records)
    {
        if (record.Type == DnsTypeA && record.Name == result.CanonicalName)
        {
            result.Addresses.push_back(record.Address);
        }
    }
    return result;
}

bool DnsNameHasSuffix(const std::string& name, const std::string& suffix)
{
    const std::string normalizedName = NormalizeName(name);
    const std::string normalizedSuffix = NormalizeName(suffix);
    if (normalizedName == normalizedSuffix)
    {
        return true;
    }
    return normalizedName.size() > normalizedSuffix.size() &&
           normalizedName.compare(normalizedName.size() - normalizedSuffix.size(),
                                  normalizedSuffix.size(),
                                  normalizedSuffix) == 0 &&
           normalizedName[normalizedName.size() - normalizedSuffix.size() - 1] == '.';
}

bool DnsNameUsesTrustedResolver(const std::string& name)
{
    return DnsNameHasSuffix(name, "ts.net");
}

DnsAnswer ResolveDnsChain(const std::string& name,
                          const std::function<DnsAnswer(const std::string&)>& query,
                          std::size_t maximumQueries)
{
    if (maximumQueries == 0)
    {
        throw std::invalid_argument("DNS query limit must be positive.");
    }
    std::string current = NormalizeName(name);
    for (std::size_t queryIndex = 0; queryIndex < maximumQueries; ++queryIndex)
    {
        DnsAnswer answer = query(current);
        answer.CanonicalName = NormalizeName(answer.CanonicalName);
        if (!answer.Addresses.empty() || answer.CanonicalName == current)
        {
            return answer;
        }
        if (answer.CanonicalName.empty())
        {
            throw std::runtime_error(
                std::format("Trusted DNS returned an empty canonical name for {}.", current));
        }
        current = std::move(answer.CanonicalName);
    }
    throw std::runtime_error(
        std::format("Trusted DNS alias chain is too deep for {}.", NormalizeName(name)));
}

DnsTarget ResolveDnsTarget(const std::string& name,
                           const std::function<DnsAnswer(const std::string&)>& query,
                           std::size_t addressIndex,
                           std::size_t maximumQueries)
{
    const DnsAnswer answer = ResolveDnsChain(name, query, maximumQueries);
    DnsTarget result;
    result.ValidationName = answer.CanonicalName;
    if (!DnsNameUsesTrustedResolver(result.ValidationName))
    {
        result.ConnectAddress = result.ValidationName;
        return result;
    }
    if (answer.Addresses.empty())
    {
        throw std::runtime_error(
            std::format("Trusted DNS returned no address for {}.", result.ValidationName));
    }
    result.ConnectAddress = answer.Addresses[addressIndex % answer.Addresses.size()];
    return result;
}

} // namespace tailgate::net::dns
