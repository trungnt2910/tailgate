#include <algorithm>

#include <gtest/gtest.h>

#include <tailgate/net/Ipv4Address.h>
#include <tailgate/net/packet/Ipv4.h>
#include <tailgate/net/packet/Tsmp.h>

TEST(Given_Tsmp, When_Ipv4TsmpPingAndBuildingPong_Then_AddressesTokenAndPortAreReturned)
{
    const tailgate::net::packet::TsmpToken token{1, 2, 3, 4, 5, 6, 7, 8};
    constexpr std::uint32_t source =
        tailgate::net::Ipv4Address::FromOctets(100, 1, 2, 3).HostOrder();
    constexpr std::uint32_t destination =
        tailgate::net::Ipv4Address::FromOctets(100, 4, 5, 6).HostOrder();
    const std::vector<std::uint8_t> ping =
        tailgate::net::packet::TsmpPacket::BuildPing(source, destination, token);

    const auto pong = tailgate::net::packet::TsmpPacket::BuildPong(ping, 41112);
    const auto parsed = pong ? tailgate::net::packet::TsmpPacket::ParsePong(*pong) : std::nullopt;

    ASSERT_TRUE(pong.has_value());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(tailgate::net::packet::Ipv4Packet::Source(*pong), destination);
    EXPECT_EQ(tailgate::net::packet::Ipv4Packet::Destination(*pong), source);
    EXPECT_EQ(parsed->Token(), token);
    EXPECT_EQ(parsed->PeerApiPort(), 41112);
}

TEST(Given_Tsmp, When_Ipv6TsmpPingAndBuildingPong_Then_AddressesAreSwapped)
{
    constexpr std::size_t Ipv6HeaderSize = 40;
    constexpr std::size_t Ipv6SourceOffset = 8;
    constexpr std::size_t Ipv6DestinationOffset = 24;
    std::vector<std::uint8_t> ping(Ipv6HeaderSize + 9);
    ping[0] = 0x60;
    ping[6] = 99;
    ping[Ipv6SourceOffset + 15] = 1;
    ping[Ipv6DestinationOffset + 15] = 2;
    ping[Ipv6HeaderSize] = 'p';
    std::copy_n(tailgate::net::packet::TsmpToken{8, 7, 6, 5, 4, 3, 2, 1}.begin(),
                tailgate::net::packet::TsmpToken{}.size(),
                ping.begin() + Ipv6HeaderSize + 1);

    const auto pong = tailgate::net::packet::TsmpPacket::BuildPong(ping, 0);

    ASSERT_TRUE(pong.has_value());
    EXPECT_EQ((*pong)[Ipv6SourceOffset + 15], 2);
    EXPECT_EQ((*pong)[Ipv6DestinationOffset + 15], 1);
    EXPECT_TRUE(tailgate::net::packet::TsmpPacket::ParsePong(*pong).has_value());
}

TEST(Given_Tsmp, When_NonTsmpPacketAndParsingOrResponding_Then_ItIsIgnored)
{
    const std::vector<std::uint8_t> packet =
        tailgate::net::packet::Ipv4Packet::Build(1, 2, 17, {'p', 1, 2, 3, 4, 5, 6, 7, 8});

    const auto pong = tailgate::net::packet::TsmpPacket::BuildPong(packet, 0);
    const auto parsed = tailgate::net::packet::TsmpPacket::ParsePong(packet);

    EXPECT_FALSE(pong.has_value());
    EXPECT_FALSE(parsed.has_value());
}

TEST(Given_Tsmp, When_TsmpPongWithoutPeerApiPortAndParsing_Then_PortIsZero)
{
    const tailgate::net::packet::TsmpToken token{1, 3, 5, 7, 2, 4, 6, 8};
    std::vector<std::uint8_t> payload{'o'};
    payload.insert(payload.end(), token.begin(), token.end());
    const std::vector<std::uint8_t> packet =
        tailgate::net::packet::Ipv4Packet::Build(1, 2, 99, payload);

    const auto pong = tailgate::net::packet::TsmpPacket::ParsePong(packet);

    ASSERT_TRUE(pong.has_value());
    EXPECT_EQ(pong->Token(), token);
    EXPECT_EQ(pong->PeerApiPort(), 0);
}

TEST(Given_Tsmp, When_FragmentedTsmpPingAndBuildingPong_Then_ItIsIgnored)
{
    const tailgate::net::packet::TsmpToken token{};
    std::vector<std::uint8_t> ping = tailgate::net::packet::TsmpPacket::BuildPing(1, 2, token);
    ping[6] = 0x20;

    const auto pong = tailgate::net::packet::TsmpPacket::BuildPong(ping, 0);

    EXPECT_FALSE(pong.has_value());
}
