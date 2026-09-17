#include <array>

#include <gtest/gtest.h>

#include <tailgate/net/packet/Ip.h>
#include <tailgate/net/packet/Ipv4.h>

namespace tailgate::tests
{

TEST(Given_IpEnvelope, When_Ipv4TcpIsFragmented_Then_AddressesAndProtocolRemainAvailable)
{
    const auto source = net::Ipv4Address::FromOctets(192, 0, 2, 1);
    const auto destination = net::Ipv4Address::FromOctets(192, 0, 2, 2);
    auto packet = net::packet::Ipv4Packet::Build(
        source.HostOrder(), destination.HostOrder(), 6, std::vector<std::uint8_t>(16));
    packet[7] = 1;

    const auto envelope = net::packet::ParseIpEnvelope(packet);
    ASSERT_TRUE(envelope);

    EXPECT_EQ(envelope->Source, net::IpAddress(source));
    EXPECT_EQ(envelope->Destination, net::IpAddress(destination));
    EXPECT_EQ(envelope->Protocol, 6);
    EXPECT_TRUE(envelope->Fragmented);
    EXPECT_FALSE(envelope->FirstFragment);
}

TEST(Given_IpEnvelope, When_Ipv4LengthDoesNotMatchDatagram_Then_EnvelopeIsRejected)
{
    const auto address = net::Ipv4Address::FromOctets(192, 0, 2, 1);
    auto packet = net::packet::Ipv4Packet::Build(address.HostOrder(), address.HostOrder(), 6, {});
    packet.push_back(0);

    const auto envelope = net::packet::ParseIpEnvelope(packet);

    EXPECT_FALSE(envelope.has_value());
}

TEST(Given_IpEnvelope, When_NoninitialIpv6FragmentArrives_Then_PayloadIsNotParsedAsAnExtension)
{
    constexpr std::size_t Ipv6HeaderLength = 40;
    constexpr std::size_t FragmentHeaderLength = 8;
    std::array<std::uint8_t, Ipv6HeaderLength + FragmentHeaderLength + 8> packet{};
    packet[0] = 0x60;
    packet[5] = FragmentHeaderLength + 8;
    packet[6] = 44;
    packet[Ipv6HeaderLength] = 6;
    packet[Ipv6HeaderLength + 3] = 8;

    const auto envelope = net::packet::ParseIpEnvelope(packet);
    ASSERT_TRUE(envelope);

    EXPECT_EQ(envelope->Protocol, 6);
    EXPECT_TRUE(envelope->Fragmented);
    EXPECT_FALSE(envelope->FirstFragment);
    EXPECT_EQ(envelope->PayloadOffset, Ipv6HeaderLength + FragmentHeaderLength);
}

TEST(Given_IpEnvelope, When_Ipv6ExtensionExceedsDatagram_Then_EnvelopeIsRejected)
{
    constexpr std::size_t Ipv6HeaderLength = 40;
    std::array<std::uint8_t, Ipv6HeaderLength + 8> packet{};
    packet[0] = 0x60;
    packet[5] = 8;
    packet[6] = 60;
    packet[Ipv6HeaderLength] = 6;
    packet[Ipv6HeaderLength + 1] = 1;

    const auto envelope = net::packet::ParseIpEnvelope(packet);

    EXPECT_FALSE(envelope.has_value());
}

} // namespace tailgate::tests
