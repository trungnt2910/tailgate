#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/hosted/Dns.h>
#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>

namespace
{

constexpr std::uint32_t SelfAddress =
    tailgate::net::Ipv4Address::FromOctets(100, 64, 0, 1).HostOrder();
constexpr std::uint32_t OtherAddress =
    tailgate::net::Ipv4Address::FromOctets(100, 64, 0, 2).HostOrder();
constexpr std::uint16_t SourcePort = 49152;
constexpr std::uint16_t TransactionId = 0x1234;

tailgate::types::netmap::NetworkConfig Network()
{
    tailgate::types::netmap::NetworkConfig result;
    result.SelfAddress("100.64.0.1");
    return result;
}

std::vector<std::uint8_t> DnsPacket(std::uint32_t source, std::uint32_t destination)
{
    return tailgate::net::packet::Ipv4UdpDatagram::Build(
        source,
        destination,
        SourcePort,
        tailgate::net::dns::DnsPort,
        tailgate::net::dns::DnsQuery::Build("host.example.ts.net", TransactionId));
}

} // namespace

TEST(Given_HostedDns, When_MagicDnsQueryIsValid_Then_HostedFrameIsProduced)
{
    tailgate::hosted::Dns subject;
    const std::vector<std::uint8_t> packet =
        DnsPacket(SelfAddress, tailgate::net::dns::MagicDnsIpv4Address);

    const tailgate::hosted::DnsResult result = subject.ProcessQuery(packet, Network());

    ASSERT_TRUE(result.RemoteFrame.has_value());
    EXPECT_EQ(result.Status, tailgate::hosted::DnsStatus::Complete);
    EXPECT_EQ(result.RemoteFrame->Type(), tailgate::hosted::MessageType::TailnetDnsQuery);
    EXPECT_EQ(result.RemoteFrame->Payload(), packet);
}

TEST(Given_HostedDns, When_MagicDnsQuerySourceIsInvalid_Then_QueryIsRejected)
{
    tailgate::hosted::Dns subject;
    const std::vector<std::uint8_t> packet =
        DnsPacket(OtherAddress, tailgate::net::dns::MagicDnsIpv4Address);

    const tailgate::hosted::DnsResult result = subject.ProcessQuery(packet, Network());

    EXPECT_EQ(result.Status, tailgate::hosted::DnsStatus::Invalid);
    EXPECT_FALSE(result.RemoteFrame.has_value());
}

TEST(Given_HostedDns, When_HostedDnsResponseIsValid_Then_LocalPacketIsProduced)
{
    tailgate::hosted::Dns subject;
    const std::vector<std::uint8_t> packet = tailgate::net::packet::Ipv4UdpDatagram::Build(
        tailgate::net::dns::MagicDnsIpv4Address,
        SelfAddress,
        tailgate::net::dns::DnsPort,
        SourcePort,
        tailgate::net::dns::DnsQuery::Build("host.example.ts.net", TransactionId));
    const tailgate::hosted::Frame frame(tailgate::hosted::MessageType::TailnetDnsResponse, packet);

    const tailgate::hosted::DnsResult result = subject.ProcessResponse(frame, Network());

    ASSERT_TRUE(result.LocalPacket.has_value());
    EXPECT_EQ(result.Status, tailgate::hosted::DnsStatus::Complete);
    EXPECT_EQ(*result.LocalPacket, packet);
}
