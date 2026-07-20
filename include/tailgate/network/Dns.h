#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace tailgate::network
{

struct DnsAnswer
{
    std::string CanonicalName;
    std::vector<std::string> Addresses;
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

[[nodiscard]] std::optional<std::string> DnsQueryName(const std::vector<std::uint8_t>& message);
[[nodiscard]] bool DnsNameHasSuffix(const std::string& name, const std::string& suffix);
[[nodiscard]] bool DnsNameUsesTrustedResolver(const std::string& name);
[[nodiscard]] DnsAnswer ResolveDnsChain(const std::string& name,
                                        const std::function<DnsAnswer(const std::string&)>& query,
                                        std::size_t maximumQueries = 8);
[[nodiscard]] DnsTarget ResolveDnsTarget(const std::string& name,
                                         const std::function<DnsAnswer(const std::string&)>& query,
                                         std::size_t addressIndex,
                                         std::size_t maximumQueries = 8);
[[nodiscard]] std::vector<std::uint8_t> BuildDnsQuery(const std::string& name,
                                                      std::uint16_t transactionId);
[[nodiscard]] DnsAnswer ParseDnsAnswer(const std::vector<std::uint8_t>& message,
                                       std::uint16_t transactionId,
                                       const std::string& queriedName);

} // namespace tailgate::network
