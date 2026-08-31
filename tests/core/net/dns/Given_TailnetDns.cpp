#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace
{

[[maybe_unused]] constexpr std::uint32_t ClientAddress =
    tailgate::net::Ipv4Address::FromOctets(100, 64, 0, 1).HostOrder();
[[maybe_unused]] constexpr std::uint32_t PeerAddress =
    tailgate::net::Ipv4Address::FromOctets(100, 64, 0, 2).HostOrder();
[[maybe_unused]] constexpr std::uint16_t ClientPort = 49152;
[[maybe_unused]] constexpr std::uint16_t TransactionId = 0x1234;

struct DnsObservation
{
    bool HasResponse = false;
    std::uint32_t Source = 0;
    std::uint32_t Destination = 0;
    std::uint16_t SourcePort = 0;
    std::uint16_t DestinationPort = 0;
    std::uint8_t ResponseCode = 0xff;
    std::vector<std::string> Addresses;
};

[[maybe_unused]] tailgate::types::netmap::NetworkConfig TestConfig()
{
    tailgate::types::netmap::NetworkConfig config;
    config.SelfAddress("100.64.0.1");
    config.SelfAddresses({"100.64.0.1"});
    config.SelfName("client.example.ts.net.");
    config.Domain("example.ts.net");
    config.MagicDnsDomain("example.ts.net");
    tailgate::types::netmap::PeerConfig peer;
    peer.Name("main.example.ts.net.");
    peer.Address("100.64.0.2");
    peer.Addresses({"100.64.0.2"});
    config.Peers({std::move(peer)});
    return config;
}

[[maybe_unused]] DnsObservation
ObserveResponse(const tailgate::types::netmap::NetworkConfig& config, const std::string& name)
{
    const std::vector<std::uint8_t> query =
        tailgate::net::dns::DnsQuery::Build(name, TransactionId);
    const std::vector<std::uint8_t> request =
        tailgate::net::packet::Ipv4UdpDatagram::Build(ClientAddress,
                                                      tailgate::net::dns::MagicDnsIpv4Address,
                                                      ClientPort,
                                                      tailgate::net::dns::DnsPort,
                                                      query);
    const std::optional<std::vector<std::uint8_t>> response =
        tailgate::net::dns::TailnetDnsResponse::Build(config, request);
    DnsObservation result;
    result.HasResponse = response.has_value();
    if (!response)
    {
        return result;
    }
    const std::optional<tailgate::net::packet::Ipv4UdpDatagram> datagram =
        tailgate::net::packet::Ipv4UdpDatagram::Parse(*response);
    if (!datagram)
    {
        return result;
    }
    result.Source = datagram->Source();
    result.Destination = datagram->Destination();
    result.SourcePort = datagram->SourcePort();
    result.DestinationPort = datagram->DestinationPort();
    try
    {
        const tailgate::net::dns::DnsAnswer answer =
            tailgate::net::dns::DnsAnswer::Parse(datagram->Payload(), TransactionId, name);
        result.ResponseCode = 0;
        result.Addresses = answer.Addresses();
    }
    catch (const tailgate::net::dns::DnsResponseError& error)
    {
        result.ResponseCode = error.ResponseCode();
    }
    return result;
}

} // namespace

TEST(Given_TailnetDns, When_TailnetFqdnAndBuildingHostedDnsResponse_Then_PeerAddressIsReturned)
{
    const tailgate::types::netmap::NetworkConfig config = TestConfig();

    const DnsObservation result = ObserveResponse(config, "main.example.ts.net");

    EXPECT_TRUE(result.HasResponse);
    EXPECT_EQ(result.Source, tailgate::net::dns::MagicDnsIpv4Address);
    EXPECT_EQ(result.Destination, ClientAddress);
    EXPECT_EQ(result.SourcePort, tailgate::net::dns::DnsPort);
    EXPECT_EQ(result.DestinationPort, ClientPort);
    EXPECT_EQ(result.ResponseCode, 0);
    EXPECT_EQ(result.Addresses, (std::vector<std::string>{"100.64.0.2"}));
}

TEST(Given_TailnetDns,
     When_UniqueSingleLabelAndBuildingHostedDnsResponse_Then_PeerAddressIsReturned)
{
    const tailgate::types::netmap::NetworkConfig config = TestConfig();

    const DnsObservation result = ObserveResponse(config, "main");

    EXPECT_TRUE(result.HasResponse);
    EXPECT_EQ(result.ResponseCode, 0);
    EXPECT_EQ(result.Addresses, (std::vector<std::string>{"100.64.0.2"}));
}

TEST(Given_TailnetDns, When_UnknownTailnetNameAndBuildingHostedDnsResponse_Then_NameErrorIsReturned)
{
    const tailgate::types::netmap::NetworkConfig config = TestConfig();

    const DnsObservation result = ObserveResponse(config, "missing.example.ts.net");

    EXPECT_TRUE(result.HasResponse);
    EXPECT_EQ(result.ResponseCode, 3);
    EXPECT_TRUE(result.Addresses.empty());
}

TEST(Given_TailnetDns, When_PublicNameAndBuildingHostedDnsResponse_Then_QueryIsRefused)
{
    const tailgate::types::netmap::NetworkConfig config = TestConfig();

    const DnsObservation result = ObserveResponse(config, "www.example.com");

    EXPECT_TRUE(result.HasResponse);
    EXPECT_EQ(result.ResponseCode, 5);
    EXPECT_TRUE(result.Addresses.empty());
}

TEST(Given_TailnetDns, When_NonMagicDnsPacketAndBuildingHostedDnsResponse_Then_ItIsIgnored)
{
    const tailgate::types::netmap::NetworkConfig config = TestConfig();
    const std::vector<std::uint8_t> query =
        tailgate::net::dns::DnsQuery::Build("main.example.ts.net", TransactionId);
    const std::vector<std::uint8_t> request = tailgate::net::packet::Ipv4UdpDatagram::Build(
        ClientAddress, PeerAddress, ClientPort, 80, query);

    const std::optional<std::vector<std::uint8_t>> response =
        tailgate::net::dns::TailnetDnsResponse::Build(config, request);

    EXPECT_FALSE(response.has_value());
}
