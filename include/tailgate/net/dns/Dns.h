#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <tailgate/base/ByteStream.h>

namespace tailgate::net::dns
{

class DnsAnswer
{
public:
    DnsAnswer(std::string canonicalName, std::vector<std::string> addresses)
        : m_canonicalName(std::move(canonicalName)), m_addresses(std::move(addresses))
    {
    }

    [[nodiscard]] static DnsAnswer Parse(const std::vector<std::uint8_t>& message,
                                         std::uint16_t transactionId,
                                         const std::string& queriedName);

    [[nodiscard]] const std::string& CanonicalName() const noexcept
    {
        return m_canonicalName;
    }

    [[nodiscard]] const std::vector<std::string>& Addresses() const noexcept
    {
        return m_addresses;
    }

private:
    std::string m_canonicalName;
    std::vector<std::string> m_addresses;
};

struct DnsTarget
{
    std::string ValidationName;
    std::string ConnectAddress;
};

class DnsResponseError final : public std::runtime_error
{
public:
    DnsResponseError(std::string queriedName, std::uint8_t responseCode);

    [[nodiscard]] const std::string& QueriedName() const noexcept;
    [[nodiscard]] std::uint8_t ResponseCode() const noexcept;

private:
    std::string m_queriedName;
    std::uint8_t m_responseCode;
};

class DnsQuery final
{
public:
    [[nodiscard]] static std::vector<std::uint8_t> Build(const std::string& name,
                                                         std::uint16_t transactionId);
    [[nodiscard]] static std::optional<std::string> Name(const std::vector<std::uint8_t>& message);
};

[[nodiscard]] bool DnsNameHasSuffix(const std::string& name, const std::string& suffix);
[[nodiscard]] bool DnsNameUsesTrustedResolver(const std::string& name);
[[nodiscard]] DnsAnswer ResolveDnsChain(const std::string& name,
                                        const std::function<DnsAnswer(const std::string&)>& query,
                                        std::size_t maximumQueries = 8);
[[nodiscard]] DnsTarget ResolveDnsTarget(const std::string& name,
                                         const std::function<DnsAnswer(const std::string&)>& query,
                                         std::size_t addressIndex,
                                         std::size_t maximumQueries = 8);
[[nodiscard]] DnsTarget ResolveDnsOverTlsTarget(tailgate::base::ByteStream& stream,
                                                const std::string& name,
                                                std::size_t addressIndex,
                                                std::size_t maximumQueries = 8);

} // namespace tailgate::net::dns
