#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/network/Dns.h>

namespace
{

void AppendName(std::vector<std::uint8_t>& message, const std::string& name)
{
    std::size_t start = 0;
    while (start < name.size())
    {
        const std::size_t dot = name.find('.', start);
        const std::size_t end = dot == std::string::npos ? name.size() : dot;
        message.push_back(static_cast<std::uint8_t>(end - start));
        message.insert(message.end(),
                       name.begin() + static_cast<std::ptrdiff_t>(start),
                       name.begin() + static_cast<std::ptrdiff_t>(end));
        start = end + 1;
    }
    message.push_back(0);
}

void AppendRecordHeader(std::vector<std::uint8_t>& message,
                        std::uint16_t type,
                        std::uint16_t length)
{
    message.insert(message.end(),
                   {static_cast<std::uint8_t>(type >> 8U),
                    static_cast<std::uint8_t>(type),
                    0,
                    1,
                    0,
                    0,
                    0,
                    30,
                    static_cast<std::uint8_t>(length >> 8U),
                    static_cast<std::uint8_t>(length)});
}

} // namespace

TEST(Given_DnsQuestion, When_ParsingName_Then_LabelsAreNormalized)
{
    const std::vector<std::uint8_t> query{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 'P',  'e',
        'e',  'r',  0x07, 'e',  'x',  'a',  'm',  'p',  'l',  'e',  0x00, 0x00, 0x01, 0x00, 0x01,
    };

    const auto name = tailgate::network::DnsQueryName(query);

    ASSERT_EQ(name, "peer.example");
    ASSERT_TRUE(tailgate::network::DnsNameHasSuffix(*name, "example."));
    ASSERT_FALSE(tailgate::network::DnsNameHasSuffix(*name, "not-example"));
}

TEST(Given_TruncatedDnsQuestion, When_ParsingName_Then_ItIsRejected)
{
    const std::vector<std::uint8_t> query{
        0x12,
        0x34,
        0x01,
        0x00,
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x05,
        'b',
        'a',
        'd',
    };

    const auto name = tailgate::network::DnsQueryName(query);

    ASSERT_FALSE(name.has_value());
}

TEST(Given_CnameDnsResponse, When_Parsing_Then_CanonicalAddressIsReturned)
{
    constexpr std::uint16_t transaction = 0x1234;
    std::vector<std::uint8_t> response =
        tailgate::network::BuildDnsQuery("alias.example", transaction);
    response[2] = 0x81;
    response[3] = 0x80;
    response[7] = 2;
    response.insert(response.end(), {0xc0, 0x0c});
    std::vector<std::uint8_t> canonicalName;
    AppendName(canonicalName, "canonical.example");
    AppendRecordHeader(response, 5, static_cast<std::uint16_t>(canonicalName.size()));
    response.insert(response.end(), canonicalName.begin(), canonicalName.end());
    AppendName(response, "canonical.example");
    AppendRecordHeader(response, 1, 4);
    response.insert(response.end(), {192, 0, 2, 10});

    const tailgate::network::DnsAnswer answer =
        tailgate::network::ParseDnsAnswer(response, transaction, "alias.example");

    EXPECT_EQ(answer.CanonicalName, "canonical.example");
    EXPECT_EQ(answer.Addresses.size(), 1U);
    EXPECT_EQ(answer.Addresses.front(), "192.0.2.10");
}

TEST(Given_DnameDnsResponse, When_Parsing_Then_SuffixIsReplaced)
{
    constexpr std::uint16_t transaction = 0x5678;
    std::vector<std::uint8_t> response =
        tailgate::network::BuildDnsQuery("host.old.example", transaction);
    response[2] = 0x81;
    response[3] = 0x80;
    response[7] = 2;
    AppendName(response, "old.example");
    std::vector<std::uint8_t> newSuffix;
    AppendName(newSuffix, "new.example");
    AppendRecordHeader(response, 39, static_cast<std::uint16_t>(newSuffix.size()));
    response.insert(response.end(), newSuffix.begin(), newSuffix.end());
    AppendName(response, "host.new.example");
    AppendRecordHeader(response, 1, 4);
    response.insert(response.end(), {198, 51, 100, 20});

    const tailgate::network::DnsAnswer answer =
        tailgate::network::ParseDnsAnswer(response, transaction, "host.old.example");

    EXPECT_EQ(answer.CanonicalName, "host.new.example");
    EXPECT_EQ(answer.Addresses.size(), 1U);
    EXPECT_EQ(answer.Addresses.front(), "198.51.100.20");
}

TEST(Given_NxdomainDnsResponse, When_Parsing_Then_TypedErrorIncludesCodeAndName)
{
    constexpr std::uint16_t transaction = 0x2468;
    std::vector<std::uint8_t> response =
        tailgate::network::BuildDnsQuery("relay.example.ts.net", transaction);
    response[2] = 0x81;
    response[3] = 0x83;
    std::optional<tailgate::network::DnsResponseError> error;

    try
    {
        (void)tailgate::network::ParseDnsAnswer(response, transaction, "relay.example.ts.net");
    }
    catch (const tailgate::network::DnsResponseError& caught)
    {
        error = caught;
    }

    ASSERT_TRUE(error);
    EXPECT_EQ(error->QueriedName(), "relay.example.ts.net");
    EXPECT_EQ(error->ResponseCode(), 3);
}

TEST(Given_TailnetDnsNames, When_SelectingResolver_Then_OnlyLabelSuffixUsesTrustedDns)
{
    const bool tailnetName = tailgate::network::DnsNameUsesTrustedResolver("Relay.Example.TS.NET.");
    const bool suffixImpersonator =
        tailgate::network::DnsNameUsesTrustedResolver("relay.examplets.net");
    const bool ordinaryName = tailgate::network::DnsNameUsesTrustedResolver("relay.example.com");

    EXPECT_TRUE(tailnetName);
    EXPECT_FALSE(suffixImpersonator);
    EXPECT_FALSE(ordinaryName);
}

TEST(Given_TrustedDnsAliasChain, When_Resolving_Then_FinalAddressIsReturned)
{
    std::vector<std::string> queriedNames;
    const auto query = [&queriedNames](const std::string& name)
    {
        queriedNames.push_back(name);
        if (name == "relay.ts.net")
        {
            return tailgate::network::DnsAnswer{.CanonicalName = "edge.example.net",
                                                .Addresses = {}};
        }
        return tailgate::network::DnsAnswer{.CanonicalName = "edge.example.net",
                                            .Addresses = {"192.0.2.40"}};
    };

    const tailgate::network::DnsAnswer answer =
        tailgate::network::ResolveDnsChain("Relay.TS.NET.", query);

    EXPECT_EQ(queriedNames, (std::vector<std::string>{"relay.ts.net", "edge.example.net"}));
    EXPECT_EQ(answer.CanonicalName, "edge.example.net");
    EXPECT_EQ(answer.Addresses, (std::vector<std::string>{"192.0.2.40"}));
}

TEST(Given_TrustedDnsNameWithoutAddress, When_Resolving_Then_CanonicalNameIsPreserved)
{
    const auto query = [](const std::string& name)
    {
        return tailgate::network::DnsAnswer{.CanonicalName = name, .Addresses = {}};
    };

    const tailgate::network::DnsAnswer answer =
        tailgate::network::ResolveDnsChain("relay.ts.net", query);

    EXPECT_EQ(answer.CanonicalName, "relay.ts.net");
    EXPECT_TRUE(answer.Addresses.empty());
}

TEST(Given_TrustedDnsTarget, When_Resolving_Then_SelectedAddressIsUsedForConnection)
{
    const auto query = [](const std::string&)
    {
        return tailgate::network::DnsAnswer{.CanonicalName = "relay.tailnet.ts.net",
                                            .Addresses = {"192.0.2.10", "192.0.2.11"}};
    };

    const tailgate::network::DnsTarget target =
        tailgate::network::ResolveDnsTarget("alias.example", query, 3);

    EXPECT_EQ(target.ValidationName, "relay.tailnet.ts.net");
    EXPECT_EQ(target.ConnectAddress, "192.0.2.11");
}

TEST(Given_UntrustedCanonicalDnsTarget, When_Resolving_Then_CanonicalNameIsUsedForConnection)
{
    const auto query = [](const std::string&)
    {
        return tailgate::network::DnsAnswer{.CanonicalName = "relay.example.com",
                                            .Addresses = {"192.0.2.20"}};
    };

    const tailgate::network::DnsTarget target =
        tailgate::network::ResolveDnsTarget("alias.example", query, 0);

    EXPECT_EQ(target.ValidationName, "relay.example.com");
    EXPECT_EQ(target.ConnectAddress, "relay.example.com");
}

TEST(Given_TrustedDnsTargetWithoutAddress, When_Resolving_Then_ItIsRejected)
{
    const auto query = [](const std::string& name)
    {
        return tailgate::network::DnsAnswer{.CanonicalName = name, .Addresses = {}};
    };
    const auto resolve = [&query]()
    {
        (void)tailgate::network::ResolveDnsTarget("relay.ts.net", query, 0);
    };

    EXPECT_THROW(resolve(), std::runtime_error);
}
