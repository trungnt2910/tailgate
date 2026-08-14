#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/net/dns/Dns.h>
#include <tailgate/net/dns/TailnetDns.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/types/netmap/NetworkMap.h>

namespace
{

constexpr std::uint32_t ClientAddress = 0x64400001U;
constexpr std::uint32_t PeerAddress = 0x64400002U;
constexpr std::uint16_t ClientPort = 49152;
constexpr std::uint16_t TransactionId = 0x1234;

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

tailgate::types::netmap::NetworkConfig TestConfig()
{
    tailgate::types::netmap::NetworkConfig config;
    config.SelfAddress = "100.64.0.1";
    config.SelfAddresses = {"100.64.0.1"};
    config.SelfName = "client.example.ts.net.";
    config.Domain = "example.ts.net";
    config.MagicDnsDomain = "example.ts.net";
    tailgate::types::netmap::PeerConfig peer;
    peer.Name = "main.example.ts.net.";
    peer.Address = "100.64.0.2";
    peer.Addresses = {"100.64.0.2"};
    config.Peers.push_back(std::move(peer));
    return config;
}

DnsObservation ObserveResponse(const tailgate::types::netmap::NetworkConfig& config,
                               const std::string& name)
{
    const std::vector<std::uint8_t> query = tailgate::net::dns::BuildDnsQuery(name, TransactionId);
    const std::vector<std::uint8_t> request =
        tailgate::net::packet::BuildUdpPacket(ClientAddress,
                                              tailgate::net::dns::MagicDnsIpv4Address,
                                              ClientPort,
                                              tailgate::net::dns::DnsPort,
                                              query);
    const std::optional<std::vector<std::uint8_t>> response =
        tailgate::net::dns::BuildTailnetDnsResponse(config, request);
    DnsObservation result;
    result.HasResponse = response.has_value();
    if (!response)
    {
        return result;
    }
    const std::optional<tailgate::net::packet::Ipv4UdpDatagram> datagram =
        tailgate::net::packet::ParseIpv4UdpDatagram(*response);
    if (!datagram)
    {
        return result;
    }
    result.Source = datagram->Source;
    result.Destination = datagram->Destination;
    result.SourcePort = datagram->SourcePort;
    result.DestinationPort = datagram->DestinationPort;
    try
    {
        const tailgate::net::dns::DnsAnswer answer =
            tailgate::net::dns::ParseDnsAnswer(datagram->Payload, TransactionId, name);
        result.ResponseCode = 0;
        result.Addresses = answer.Addresses;
    }
    catch (const tailgate::net::dns::DnsResponseError& error)
    {
        result.ResponseCode = error.ResponseCode();
    }
    return result;
}

} // namespace

TEST(Given_TailnetFqdn, When_BuildingHostedDnsResponse_Then_PeerAddressIsReturned)
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

TEST(Given_UniqueSingleLabel, When_BuildingHostedDnsResponse_Then_PeerAddressIsReturned)
{
    const tailgate::types::netmap::NetworkConfig config = TestConfig();

    const DnsObservation result = ObserveResponse(config, "main");

    EXPECT_TRUE(result.HasResponse);
    EXPECT_EQ(result.ResponseCode, 0);
    EXPECT_EQ(result.Addresses, (std::vector<std::string>{"100.64.0.2"}));
}

TEST(Given_UnknownTailnetName, When_BuildingHostedDnsResponse_Then_NameErrorIsReturned)
{
    const tailgate::types::netmap::NetworkConfig config = TestConfig();

    const DnsObservation result = ObserveResponse(config, "missing.example.ts.net");

    EXPECT_TRUE(result.HasResponse);
    EXPECT_EQ(result.ResponseCode, 3);
    EXPECT_TRUE(result.Addresses.empty());
}

TEST(Given_PublicName, When_BuildingHostedDnsResponse_Then_QueryIsRefused)
{
    const tailgate::types::netmap::NetworkConfig config = TestConfig();

    const DnsObservation result = ObserveResponse(config, "www.example.com");

    EXPECT_TRUE(result.HasResponse);
    EXPECT_EQ(result.ResponseCode, 5);
    EXPECT_TRUE(result.Addresses.empty());
}

TEST(Given_NonMagicDnsPacket, When_BuildingHostedDnsResponse_Then_ItIsIgnored)
{
    const tailgate::types::netmap::NetworkConfig config = TestConfig();
    const std::vector<std::uint8_t> query =
        tailgate::net::dns::BuildDnsQuery("main.example.ts.net", TransactionId);
    const std::vector<std::uint8_t> request =
        tailgate::net::packet::BuildUdpPacket(ClientAddress, PeerAddress, ClientPort, 80, query);

    const std::optional<std::vector<std::uint8_t>> response =
        tailgate::net::dns::BuildTailnetDnsResponse(config, request);

    EXPECT_FALSE(response.has_value());
}
