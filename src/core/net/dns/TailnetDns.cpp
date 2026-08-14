#include <tailgate/net/dns/TailnetDns.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <boost/algorithm/hex.hpp>
#include <boost/algorithm/string/case_conv.hpp>

#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/packet/Ipv4.h>

namespace tailgate::net::dns
{

using tailgate::net::packet::BuildUdpPacket;
using tailgate::net::packet::Ipv4UdpDatagram;
using tailgate::net::packet::ParseIpv4;
using tailgate::net::packet::ParseIpv4UdpDatagram;

namespace
{

constexpr std::size_t DnsHeaderSize = 12;
constexpr std::size_t DnsQuestionFooterSize = 4;
constexpr std::size_t MaximumDnsLabelLength = 63;
constexpr std::uint16_t DnsQueryResponseFlag = 0x8000;
constexpr std::uint16_t DnsAuthoritativeFlag = 0x0400;
constexpr std::uint16_t DnsRecursionDesiredFlag = 0x0100;
constexpr std::uint16_t DnsOpcodeMask = 0x7800;
constexpr std::uint16_t DnsResponseCodeNameError = 3;
constexpr std::uint16_t DnsResponseCodeRefused = 5;
constexpr std::uint16_t DnsTypeA = 1;
constexpr std::uint16_t DnsTypeAaaa = 28;
constexpr std::uint16_t DnsTypeAny = 255;
constexpr std::uint16_t DnsClassInternet = 1;
constexpr std::uint32_t TailnetRecordTimeToLive = 30;
constexpr std::uint16_t DnsQuestionNamePointer = 0xc00c;

struct DnsQuestion
{
    std::string Name;
    std::uint16_t Type = 0;
    std::uint16_t Class = 0;
    std::size_t EndOffset = 0;
};

struct TailnetHost
{
    bool Found = false;
    std::vector<std::uint32_t> Ipv4;
    std::vector<std::array<std::uint8_t, 16>> Ipv6;
};

void Append16(std::vector<std::uint8_t>& output, std::uint16_t value)
{
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

void Append32(std::vector<std::uint8_t>& output, std::uint32_t value)
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

std::string NormalizeName(std::string value)
{
    while (!value.empty() && value.back() == '.')
    {
        value.pop_back();
    }
    boost::algorithm::to_lower(value);
    return value;
}

std::optional<DnsQuestion> ParseQuestion(const std::vector<std::uint8_t>& query)
{
    if (query.size() < DnsHeaderSize || Read16(query, 4) != 1)
    {
        return std::nullopt;
    }
    DnsQuestion question;
    std::size_t offset = DnsHeaderSize;
    while (offset < query.size() && query[offset] != 0)
    {
        const std::size_t length = query[offset++];
        if (length == 0 || length > MaximumDnsLabelLength || offset + length > query.size())
        {
            return std::nullopt;
        }
        if (!question.Name.empty())
        {
            question.Name.push_back('.');
        }
        question.Name.append(query.begin() + static_cast<std::ptrdiff_t>(offset),
                             query.begin() + static_cast<std::ptrdiff_t>(offset + length));
        offset += length;
    }
    if (question.Name.empty() || offset >= query.size() ||
        offset + 1 + DnsQuestionFooterSize > query.size())
    {
        return std::nullopt;
    }
    ++offset;
    question.Type = Read16(query, offset);
    question.Class = Read16(query, offset + 2);
    question.EndOffset = offset + DnsQuestionFooterSize;
    question.Name = NormalizeName(std::move(question.Name));
    return question;
}

std::string FirstLabel(const std::string& name)
{
    const std::string normalized = NormalizeName(name);
    return normalized.substr(0, normalized.find('.'));
}

std::vector<std::uint32_t> Ipv4Addresses(const std::vector<std::string>& addresses,
                                         const std::string& primary)
{
    std::vector<std::uint32_t> result;
    const auto append = [&](const std::string& text)
    {
        const std::optional<std::uint32_t> address = ParseIpv4(text);
        if (address && std::find(result.begin(), result.end(), *address) == result.end())
        {
            result.push_back(*address);
        }
    };
    for (const std::string& address : addresses)
    {
        append(address);
    }
    append(primary);
    return result;
}

std::optional<std::array<std::uint8_t, 16>> ParseIpv6(const std::string& text)
{
    if (text.empty() || text.find('.') != std::string::npos || text.find("::") != text.rfind("::"))
    {
        return std::nullopt;
    }
    const std::size_t compression = text.find("::");
    const auto parseSide = [](const std::string& side) -> std::optional<std::vector<std::uint16_t>>
    {
        std::vector<std::uint16_t> words;
        std::size_t start = 0;
        while (start < side.size())
        {
            const std::size_t colon = side.find(':', start);
            const std::size_t end = colon == std::string::npos ? side.size() : colon;
            if (end == start || end - start > 4)
            {
                return std::nullopt;
            }
            std::string wordText = side.substr(start, end - start);
            if (wordText.size() % 2 != 0)
            {
                wordText.insert(wordText.begin(), '0');
            }
            std::vector<std::uint8_t> bytes;
            try
            {
                boost::algorithm::unhex(wordText, std::back_inserter(bytes));
            }
            catch (const boost::algorithm::hex_decode_error&)
            {
                return std::nullopt;
            }
            std::uint16_t word = 0;
            for (const std::uint8_t byte : bytes)
            {
                word = static_cast<std::uint16_t>((word << 8U) | byte);
            }
            words.push_back(word);
            start = end + 1;
        }
        return words;
    };

    const std::string leftText =
        compression == std::string::npos ? text : text.substr(0, compression);
    const std::string rightText =
        compression == std::string::npos ? std::string{} : text.substr(compression + 2);
    const std::optional<std::vector<std::uint16_t>> left = parseSide(leftText);
    const std::optional<std::vector<std::uint16_t>> right = parseSide(rightText);
    if (!left || !right || (compression == std::string::npos && left->size() != 8) ||
        (compression != std::string::npos && left->size() + right->size() >= 8))
    {
        return std::nullopt;
    }
    std::vector<std::uint16_t> words = *left;
    words.insert(words.end(), 8 - left->size() - right->size(), 0);
    words.insert(words.end(), right->begin(), right->end());
    std::array<std::uint8_t, 16> result{};
    for (std::size_t index = 0; index < words.size(); ++index)
    {
        result[index * 2] = static_cast<std::uint8_t>(words[index] >> 8U);
        result[index * 2 + 1] = static_cast<std::uint8_t>(words[index]);
    }
    return result;
}

std::vector<std::array<std::uint8_t, 16>> Ipv6Addresses(const std::vector<std::string>& addresses)
{
    std::vector<std::array<std::uint8_t, 16>> result;
    for (const std::string& text : addresses)
    {
        const std::optional<std::array<std::uint8_t, 16>> address = ParseIpv6(text);
        if (address && std::find(result.begin(), result.end(), *address) == result.end())
        {
            result.push_back(*address);
        }
    }
    return result;
}

TailnetHost FindHost(const tailgate::types::netmap::NetworkConfig& config,
                     const std::string& queriedName)
{
    struct Node
    {
        const std::string* Name = nullptr;
        const std::string* PrimaryAddress = nullptr;
        const std::vector<std::string>* Addresses = nullptr;
    };

    std::vector<Node> nodes;
    nodes.push_back(Node{.Name = &config.SelfName,
                         .PrimaryAddress = &config.SelfAddress,
                         .Addresses = &config.SelfAddresses});
    for (const tailgate::types::netmap::PeerConfig& peer : config.Peers)
    {
        nodes.push_back(Node{
            .Name = &peer.Name, .PrimaryAddress = &peer.Address, .Addresses = &peer.Addresses});
    }

    const bool singleLabel = queriedName.find('.') == std::string::npos;
    const Node* match = nullptr;
    for (const Node& node : nodes)
    {
        const std::string normalized = NormalizeName(*node.Name);
        const bool matches =
            normalized == queriedName || (singleLabel && FirstLabel(normalized) == queriedName);
        if (!matches)
        {
            continue;
        }
        if (match != nullptr)
        {
            return {};
        }
        match = &node;
    }
    if (match == nullptr)
    {
        return {};
    }
    return TailnetHost{.Found = true,
                       .Ipv4 = Ipv4Addresses(*match->Addresses, *match->PrimaryAddress),
                       .Ipv6 = Ipv6Addresses(*match->Addresses)};
}

bool IsTailnetName(const tailgate::types::netmap::NetworkConfig& config, const std::string& name)
{
    if (name.find('.') == std::string::npos)
    {
        return true;
    }
    const std::string magicDomain =
        config.MagicDnsDomain.empty() ? config.Domain : config.MagicDnsDomain;
    return !magicDomain.empty() && DnsNameHasSuffix(name, magicDomain);
}

std::vector<std::uint8_t> BuildDnsResponse(const std::vector<std::uint8_t>& query,
                                           const DnsQuestion& question,
                                           const std::vector<std::uint32_t>& ipv4,
                                           const std::vector<std::array<std::uint8_t, 16>>& ipv6,
                                           std::uint16_t responseCode)
{
    const std::uint16_t requestFlags = Read16(query, 2);
    const std::uint16_t flags = DnsQueryResponseFlag | DnsAuthoritativeFlag |
                                (requestFlags & DnsRecursionDesiredFlag) | responseCode;
    std::vector<std::uint8_t> response;
    response.reserve(question.EndOffset + ipv4.size() * 16U + ipv6.size() * 28U);
    Append16(response, Read16(query, 0));
    Append16(response, flags);
    Append16(response, 1);
    Append16(response, static_cast<std::uint16_t>(ipv4.size() + ipv6.size()));
    Append16(response, 0);
    Append16(response, 0);
    response.insert(response.end(),
                    query.begin() + static_cast<std::ptrdiff_t>(DnsHeaderSize),
                    query.begin() + static_cast<std::ptrdiff_t>(question.EndOffset));
    for (const std::uint32_t address : ipv4)
    {
        Append16(response, DnsQuestionNamePointer);
        Append16(response, DnsTypeA);
        Append16(response, DnsClassInternet);
        Append32(response, TailnetRecordTimeToLive);
        Append16(response, sizeof(address));
        Append32(response, address);
    }
    for (const std::array<std::uint8_t, 16>& address : ipv6)
    {
        Append16(response, DnsQuestionNamePointer);
        Append16(response, DnsTypeAaaa);
        Append16(response, DnsClassInternet);
        Append32(response, TailnetRecordTimeToLive);
        Append16(response, static_cast<std::uint16_t>(address.size()));
        response.insert(response.end(), address.begin(), address.end());
    }
    return response;
}

} // namespace

std::optional<std::vector<std::uint8_t>>
BuildTailnetDnsResponse(const tailgate::types::netmap::NetworkConfig& config,
                        const std::vector<std::uint8_t>& request)
{
    const std::optional<Ipv4UdpDatagram> datagram = ParseIpv4UdpDatagram(request);
    if (!datagram || datagram->Destination != MagicDnsIpv4Address ||
        datagram->DestinationPort != DnsPort || datagram->Payload.size() < DnsHeaderSize)
    {
        return std::nullopt;
    }
    const std::uint16_t flags = Read16(datagram->Payload, 2);
    const std::optional<DnsQuestion> question = ParseQuestion(datagram->Payload);
    if ((flags & (DnsQueryResponseFlag | DnsOpcodeMask)) != 0 || !question)
    {
        return std::nullopt;
    }

    std::vector<std::uint32_t> ipv4;
    std::vector<std::array<std::uint8_t, 16>> ipv6;
    std::uint16_t responseCode = 0;
    if (question->Class != DnsClassInternet ||
        (question->Type != DnsTypeA && question->Type != DnsTypeAaaa &&
         question->Type != DnsTypeAny))
    {
    }
    else if (!IsTailnetName(config, question->Name))
    {
        responseCode = DnsResponseCodeRefused;
    }
    else
    {
        const TailnetHost host = FindHost(config, question->Name);
        if (!host.Found)
        {
            responseCode = DnsResponseCodeNameError;
        }
        else
        {
            if (question->Type == DnsTypeA || question->Type == DnsTypeAny)
            {
                ipv4 = host.Ipv4;
            }
            if (question->Type == DnsTypeAaaa || question->Type == DnsTypeAny)
            {
                ipv6 = host.Ipv6;
            }
        }
    }
    const std::vector<std::uint8_t> dnsResponse =
        BuildDnsResponse(datagram->Payload, *question, ipv4, ipv6, responseCode);
    return BuildUdpPacket(
        MagicDnsIpv4Address, datagram->Source, DnsPort, datagram->SourcePort, dnsResponse);
}

} // namespace tailgate::net::dns
