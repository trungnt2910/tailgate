#include <cstdint>
#include <string>

#include <gtest/gtest.h>

#include <tailgate/net/dns/Dns.h>

#include "fakes/net/dns/FakeByteStream.h"

TEST(Given_DnsOverTls, When_TargetIsResolved_Then_CoreOwnsFramingAndAddressSelection)
{
    tailgate::tests::fakes::net::dns::FakeByteStream stream;

    const tailgate::net::dns::DnsTarget target =
        tailgate::net::dns::ResolveDnsOverTlsTarget(stream, "relay.example.ts.net", 0);

    EXPECT_EQ(target.ValidationName, "relay.example.ts.net");
    EXPECT_EQ(target.ConnectAddress, "192.0.2.40");
    EXPECT_GT(stream.Written().size(), 2U);
}
