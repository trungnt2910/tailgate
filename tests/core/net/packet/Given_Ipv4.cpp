#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/net/packet/Ipv4.h>

TEST(Given_Ipv4UdpPacket, When_Parsing_Then_EndpointsAndPayloadAreReturned)
{
    constexpr std::uint32_t source = 0xc0000201U;
    constexpr std::uint32_t destination = 0xc6336402U;
    constexpr std::uint16_t sourcePort = 53000;
    constexpr std::uint16_t destinationPort = 53;
    const std::vector<std::uint8_t> payload{0x12, 0x34, 0x01, 0x00};
    const std::vector<std::uint8_t> packet = tailgate::net::packet::BuildUdpPacket(
        source, destination, sourcePort, destinationPort, payload);

    const std::optional<tailgate::net::packet::Ipv4UdpDatagram> datagram =
        tailgate::net::packet::ParseIpv4UdpDatagram(packet);

    ASSERT_TRUE(datagram);
    EXPECT_EQ(datagram->Source, source);
    EXPECT_EQ(datagram->Destination, destination);
    EXPECT_EQ(datagram->SourcePort, sourcePort);
    EXPECT_EQ(datagram->DestinationPort, destinationPort);
    EXPECT_EQ(datagram->Payload, payload);
}

TEST(Given_TruncatedIpv4UdpPacket, When_Parsing_Then_ItIsRejected)
{
    const std::vector<std::uint8_t> packet{0x45, 0x00, 0x00};

    const std::optional<tailgate::net::packet::Ipv4UdpDatagram> datagram =
        tailgate::net::packet::ParseIpv4UdpDatagram(packet);

    EXPECT_FALSE(datagram);
}
