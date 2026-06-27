#include <gtest/gtest.h>

#include "tailgate/network/Dns.h"

TEST(Tailgate, GivenDnsQuestion_WhenParsingName_ThenLabelsAreNormalized)
{
    const std::vector<std::uint8_t> query{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        'I',  's',  'h',  'a',  'r',  0x02, 'n',  't',  0x00, 0x00, 0x01, 0x00, 0x01,
    };

    const auto name = tailgate::network::DnsQueryName(query);

    ASSERT_EQ(name, "ishar.nt");
    ASSERT_TRUE(tailgate::network::DnsNameHasSuffix(*name, "nt."));
    ASSERT_FALSE(tailgate::network::DnsNameHasSuffix(*name, "not-nt"));
}

TEST(Tailgate, GivenTruncatedDnsQuestion_WhenParsingName_ThenItIsRejected)
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
