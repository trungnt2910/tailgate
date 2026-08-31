#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/packet/Ipv4.h>

TEST(Given_Ipv4, When_Ipv4UdpPacketAndParsing_Then_EndpointsAndPayloadAreReturned)
{
    constexpr std::uint32_t source =
        tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 1).HostOrder();
    constexpr std::uint32_t destination =
        tailgate::net::Ipv4Address::FromOctets(198, 51, 100, 2).HostOrder();
    constexpr std::uint16_t sourcePort = 53000;
    constexpr std::uint16_t destinationPort = 53;
    const std::vector<std::uint8_t> payload{0x12, 0x34, 0x01, 0x00};
    const std::vector<std::uint8_t> packet = tailgate::net::packet::Ipv4UdpDatagram::Build(
        source, destination, sourcePort, destinationPort, payload);

    const std::optional<tailgate::net::packet::Ipv4UdpDatagram> datagram =
        tailgate::net::packet::Ipv4UdpDatagram::Parse(packet);

    ASSERT_TRUE(datagram);
    EXPECT_EQ(datagram->Source(), source);
    EXPECT_EQ(datagram->Destination(), destination);
    EXPECT_EQ(datagram->SourcePort(), sourcePort);
    EXPECT_EQ(datagram->DestinationPort(), destinationPort);
    EXPECT_EQ(datagram->Payload(), payload);
}

TEST(Given_Ipv4, When_TruncatedIpv4UdpPacketAndParsing_Then_ItIsRejected)
{
    const std::vector<std::uint8_t> packet{0x45, 0x00, 0x00};

    const std::optional<tailgate::net::packet::Ipv4UdpDatagram> datagram =
        tailgate::net::packet::Ipv4UdpDatagram::Parse(packet);

    EXPECT_FALSE(datagram);
}
