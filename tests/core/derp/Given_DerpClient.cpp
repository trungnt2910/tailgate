#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/protocol/Crypto.h>
#include <tailgate/protocol/DerpClient.h>

#include "support/ScriptedByteStream.h"

namespace
{

constexpr std::uint8_t ServerKeyFrame = 0x01;
constexpr std::uint8_t ClientInfoFrame = 0x02;
constexpr std::uint8_t ServerInfoFrame = 0x03;
constexpr std::uint8_t SendPacketFrame = 0x04;
constexpr std::uint8_t ReceivePacketFrame = 0x05;
constexpr std::uint8_t KeepAliveFrame = 0x06;
constexpr std::uint8_t PreferredFrame = 0x07;
constexpr std::uint8_t PeerGoneFrame = 0x08;
constexpr std::uint8_t PingFrame = 0x12;
constexpr std::uint8_t PongFrame = 0x13;
constexpr std::uint8_t HealthFrame = 0x14;
constexpr std::size_t MaximumFrameSize = 1U << 20;
constexpr std::size_t DerpKeySize = 32;
constexpr std::size_t CryptoBoxNonceSize = 24;
constexpr std::size_t CryptoBoxMacSize = 16;
constexpr std::array<std::uint8_t, 8> DerpMagic{'D', 'E', 'R', 'P', 0xf0, 0x9f, 0x94, 0x91};

std::vector<std::uint8_t> Frame(std::uint8_t type, const std::vector<std::uint8_t>& payload)
{
    const std::uint32_t size = static_cast<std::uint32_t>(payload.size());
    std::vector<std::uint8_t> result{
        type,
        static_cast<std::uint8_t>(size >> 24U),
        static_cast<std::uint8_t>(size >> 16U),
        static_cast<std::uint8_t>(size >> 8U),
        static_cast<std::uint8_t>(size),
    };
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

std::vector<std::uint8_t> PacketPayload(const tailgate::protocol::DerpClient::Key& source,
                                        const std::vector<std::uint8_t>& packet)
{
    std::vector<std::uint8_t> result(source.begin(), source.end());
    result.insert(result.end(), packet.begin(), packet.end());
    return result;
}

std::vector<std::uint8_t> Greeting(const tailgate::protocol::DerpClient::Key& serverKey)
{
    std::vector<std::uint8_t> result(DerpMagic.begin(), DerpMagic.end());
    result.insert(result.end(), serverKey.begin(), serverKey.end());
    return Frame(ServerKeyFrame, result);
}

} // namespace

TEST(Given_DerpClient, When_BuildingClientInfo_Then_EnvelopeContainsNodeKeyAndFreshNonce)
{
    const tailgate::protocol::Bytes32 clientPrivate = tailgate::protocol::GeneratePrivateKey();
    const tailgate::protocol::Bytes32 clientPublic =
        tailgate::protocol::X25519PublicFromPrivate(clientPrivate);
    const tailgate::protocol::Bytes32 serverPublic =
        tailgate::protocol::X25519PublicFromPrivate(tailgate::protocol::GeneratePrivateKey());

    const std::vector<std::uint8_t> first =
        tailgate::protocol::DerpClient::BuildClientInfo(clientPrivate, clientPublic, serverPublic);
    const std::vector<std::uint8_t> second =
        tailgate::protocol::DerpClient::BuildClientInfo(clientPrivate, clientPublic, serverPublic);

    EXPECT_GT(first.size(), clientPublic.size());
    EXPECT_EQ(first.size(), second.size());
    EXPECT_TRUE(std::equal(clientPublic.begin(), clientPublic.end(), first.begin()));
    EXPECT_TRUE(std::equal(clientPublic.begin(), clientPublic.end(), second.begin()));
    EXPECT_NE(first, second);
}

TEST(Given_DerpClient, When_ConnectingWithAuthenticator_Then_UpgradeAndIdentityAreExchanged)
{
    tailgate::test::ScriptedByteStream stream;
    tailgate::protocol::DerpClient::Key serverKey{};
    serverKey[0] = 42;
    std::vector<std::uint8_t> input{'H', 'T', 'T', 'P', '/',  '1',  '.',  '1', ' ',
                                    '1', '0', '1', ' ', 'S',  'w',  'i',  't', 'c',
                                    'h', 'i', 'n', 'g', '\r', '\n', '\r', '\n'};
    const std::vector<std::uint8_t> greeting = Greeting(serverKey);
    const std::vector<std::uint8_t> serverInfo =
        Frame(ServerInfoFrame, std::vector<std::uint8_t>(CryptoBoxNonceSize + CryptoBoxMacSize));
    input.insert(input.end(), greeting.begin(), greeting.end());
    input.insert(input.end(), serverInfo.begin(), serverInfo.end());
    stream.QueueRead(std::move(input));
    std::optional<tailgate::protocol::DerpClient::Key> authenticatedServer;
    const auto authenticate = [&](const tailgate::protocol::DerpClient::Key& key)
    {
        authenticatedServer = key;
        return std::vector<std::uint8_t>(DerpKeySize + CryptoBoxNonceSize + CryptoBoxMacSize);
    };
    tailgate::protocol::DerpClient client(stream, authenticate);

    client.Connect("derp.example.com");

    EXPECT_EQ(authenticatedServer, std::optional(serverKey));
    EXPECT_TRUE(std::search(stream.Written.begin(),
                            stream.Written.end(),
                            std::begin("GET /derp HTTP/1.1"),
                            std::end("GET /derp HTTP/1.1") - 1) != stream.Written.end());
    EXPECT_NE(std::find(stream.Written.begin(), stream.Written.end(), ClientInfoFrame),
              stream.Written.end());
}

TEST(Given_DerpClient, When_SendingPacket_Then_DestinationAndPayloadAreFramed)
{
    tailgate::test::ScriptedByteStream stream;
    tailgate::protocol::DerpClient::Key destination{};
    destination[0] = 42;
    const std::vector<std::uint8_t> packet{1, 2, 3, 4};
    const std::vector<std::uint8_t> expected =
        Frame(SendPacketFrame, PacketPayload(destination, packet));
    tailgate::protocol::DerpClient client(stream, {}, {});

    client.Send(destination, packet);

    EXPECT_EQ(stream.Written, expected);
    EXPECT_FALSE(client.HasPendingOutput());
}

TEST(Given_DerpClient, When_ReceivePacketIsFragmented_Then_ItIsReturnedAfterFinalFragment)
{
    tailgate::test::ScriptedByteStream stream;
    tailgate::protocol::DerpClient::Key source{};
    source[0] = 42;
    const std::vector<std::uint8_t> packet{1, 2, 3, 4};
    const std::vector<std::uint8_t> frame =
        Frame(ReceivePacketFrame, PacketPayload(source, packet));
    stream.QueueRead({frame.begin(), frame.begin() + 3});
    stream.QueueRead({frame.begin() + 3, frame.end()});
    tailgate::protocol::DerpClient client(stream, {}, {});

    const std::optional<tailgate::protocol::DerpClient::Packet> beforeFinal =
        client.ReceiveAvailable();
    const std::optional<tailgate::protocol::DerpClient::Packet> afterFinal =
        client.ReceiveAvailable();

    EXPECT_FALSE(beforeFinal.has_value());
    EXPECT_TRUE(afterFinal.has_value());
    EXPECT_EQ(afterFinal.value().Source, source);
    EXPECT_EQ(afterFinal.value().Payload, packet);
}

TEST(Given_DerpClient, When_ReceivePacketsAreCoalesced_Then_BufferedPacketNeedsNoAdditionalRead)
{
    tailgate::test::ScriptedByteStream stream;
    tailgate::protocol::DerpClient::Key firstSource{};
    tailgate::protocol::DerpClient::Key secondSource{};
    firstSource[0] = 1;
    secondSource[0] = 2;
    std::vector<std::uint8_t> input = Frame(ReceivePacketFrame, PacketPayload(firstSource, {3}));
    const std::vector<std::uint8_t> second =
        Frame(ReceivePacketFrame, PacketPayload(secondSource, {4}));
    input.insert(input.end(), second.begin(), second.end());
    stream.QueueRead(std::move(input));
    tailgate::protocol::DerpClient client(stream, {}, {});

    const std::optional<tailgate::protocol::DerpClient::Packet> first = client.ReceiveAvailable();
    const std::size_t readsAfterFirst = stream.ReadCalls;
    const std::optional<tailgate::protocol::DerpClient::Packet> secondPacket =
        client.ReceiveAvailable();

    EXPECT_TRUE(first.has_value());
    EXPECT_TRUE(secondPacket.has_value());
    EXPECT_EQ(first.value().Source, firstSource);
    EXPECT_EQ(first.value().Payload, (std::vector<std::uint8_t>{3}));
    EXPECT_EQ(secondPacket.value().Source, secondSource);
    EXPECT_EQ(secondPacket.value().Payload, (std::vector<std::uint8_t>{4}));
    EXPECT_EQ(stream.ReadCalls, readsAfterFirst);
}

TEST(Given_DerpClient, When_ControlAndDataFramesAreBatched_Then_OnlyDataIsReturnedAndPingIsAcked)
{
    tailgate::test::ScriptedByteStream stream;
    tailgate::protocol::DerpClient::Key source{};
    source[0] = 42;
    std::vector<std::uint8_t> input = Frame(KeepAliveFrame, {});
    const std::vector<std::vector<std::uint8_t>> remaining{
        Frame(HealthFrame, {'o', 'k'}),
        Frame(PeerGoneFrame, std::vector<std::uint8_t>(DerpKeySize)),
        Frame(PingFrame, {1, 2, 3}),
        Frame(ReceivePacketFrame, PacketPayload(source, {4, 5, 6})),
    };
    for (const std::vector<std::uint8_t>& frame : remaining)
    {
        input.insert(input.end(), frame.begin(), frame.end());
    }
    stream.QueueRead(std::move(input));
    tailgate::protocol::DerpClient client(stream, {}, {});
    const std::vector<std::uint8_t> expectedPong = Frame(PongFrame, {1, 2, 3});

    const std::vector<tailgate::protocol::DerpClient::Packet> packets =
        client.ReceiveAvailableBatch();

    EXPECT_EQ(packets.size(), 1U);
    EXPECT_EQ(packets.at(0).Source, source);
    EXPECT_EQ(packets.at(0).Payload, (std::vector<std::uint8_t>{4, 5, 6}));
    EXPECT_EQ(stream.Written, expectedPong);
}

TEST(Given_DerpClient, When_WriteWouldBlock_Then_FlushResumesPendingFrame)
{
    tailgate::test::ScriptedByteStream stream;
    stream.BlockedWrites = 1;
    tailgate::protocol::DerpClient client(stream, {}, {});
    tailgate::protocol::DerpClient::Key destination{};
    const std::vector<std::uint8_t> expected =
        Frame(SendPacketFrame, PacketPayload(destination, {1}));

    client.Send(destination, {1});
    const bool pendingBeforeFlush = client.HasPendingOutput();
    client.Flush();

    EXPECT_TRUE(pendingBeforeFlush);
    EXPECT_FALSE(client.HasPendingOutput());
    EXPECT_EQ(stream.Written, expected);
}

TEST(Given_DerpClient, When_FrameExceedsProtocolLimit_Then_ReceiveRejectsIt)
{
    tailgate::test::ScriptedByteStream stream;
    const std::uint32_t oversized = static_cast<std::uint32_t>(MaximumFrameSize + 1);
    stream.QueueRead({ReceivePacketFrame,
                      static_cast<std::uint8_t>(oversized >> 24U),
                      static_cast<std::uint8_t>(oversized >> 16U),
                      static_cast<std::uint8_t>(oversized >> 8U),
                      static_cast<std::uint8_t>(oversized)});
    tailgate::protocol::DerpClient client(stream, {}, {});
    const auto receive = [&]()
    {
        (void)client.ReceiveAvailable();
    };

    EXPECT_THROW(receive(), std::runtime_error);
}

TEST(Given_DerpClient, When_SettingPreference_Then_BooleanFrameIsSent)
{
    tailgate::test::ScriptedByteStream stream;
    tailgate::protocol::DerpClient client(stream, {}, {});
    const std::vector<std::uint8_t> expected = Frame(PreferredFrame, {1});

    client.SetPreferred(true);

    EXPECT_EQ(stream.Written, expected);
}
