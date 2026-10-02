#include <array>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/derp/Client.h>

#include "bg/tstun/VpnCallbackStream.h"
#include "support/ScriptedByteStream.h"

namespace tailgate::uwp::tests
{
namespace
{

class Given_VpnCallbackStream : public testing::Test
{
protected:
    test::ScriptedByteStream Socket;
    bg::VpnCallbackStream Stream{Socket};
};

TEST_F(Given_VpnCallbackStream, When_Authenticating_Then_ReadsUnderlyingSocket)
{
    Socket.QueueRead({1, 2, 3});

    const auto bytes = Stream.TryReadSome(3);

    EXPECT_EQ(bytes, (std::vector<std::uint8_t>{1, 2, 3}));
    EXPECT_EQ(Socket.ReadCalls, 1U);
}

TEST_F(Given_VpnCallbackStream, When_WindowsOwnsReceive_Then_EmptyQueueDoesNotReadSocket)
{
    Socket.QueueRead({9});
    Stream.UseCallbackInput();

    const auto bytes = Stream.TryReadSome(1);
    const auto buffered = Stream.HasBufferedInput();

    EXPECT_FALSE(bytes);
    EXPECT_FALSE(buffered);
    EXPECT_EQ(Socket.ReadCalls, 0U);
}

TEST_F(Given_VpnCallbackStream, When_ServerPingArrivesInFragments_Then_CoreRepliesWithoutSocketRead)
{
    Stream.UseCallbackInput();
    derp::DerpClient client(Stream, {}, {});
    const std::vector<std::uint8_t> ping{0x12, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8};
    auto pong = ping;
    pong[0] = 0x13;

    const bool first = Stream.AppendInput(std::span(ping).first(3));
    const auto firstPackets = client.ReceiveAvailableBatch();
    const bool prematureReply = !Socket.Written.empty();
    const bool second = Stream.AppendInput(std::span(ping).subspan(3));
    const auto secondPackets = client.ReceiveAvailableBatch();

    EXPECT_TRUE(first);
    EXPECT_TRUE(second);
    EXPECT_TRUE(firstPackets.empty());
    EXPECT_TRUE(secondPackets.empty());
    EXPECT_FALSE(prematureReply);
    EXPECT_EQ(Socket.Written, pong);
    EXPECT_EQ(Socket.ReadCalls, 0U);
}

TEST_F(Given_VpnCallbackStream, When_PongAndPingAreCoalesced_Then_CoreConsumesBothAndRepliesOnce)
{
    Stream.UseCallbackInput();
    derp::DerpClient client(Stream, {}, {});
    const std::vector<std::uint8_t> pong{0x13, 0, 0, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8};
    auto input = pong;
    auto ping = pong;
    ping[0] = 0x12;
    input.insert(input.end(), ping.begin(), ping.end());

    const bool appended = Stream.AppendInput(input);
    const auto packets = client.ReceiveAvailableBatch();

    EXPECT_TRUE(appended);
    EXPECT_TRUE(packets.empty());
    EXPECT_EQ(Socket.Written, pong);
    EXPECT_FALSE(Stream.HasBufferedInput());
    EXPECT_EQ(Socket.ReadCalls, 0U);
}

TEST_F(Given_VpnCallbackStream, When_QueueLimitIsExceeded_Then_RejectsInputAndPreservesQueuedBytes)
{
    Stream.UseCallbackInput();
    const std::array<std::uint8_t, 1> first{7};
    const std::vector<std::uint8_t> excessive(bg::VpnCallbackStream::MaximumBufferedBytes, 0);
    ASSERT_TRUE(Stream.AppendInput(first));

    const bool appended = Stream.AppendInput(excessive);
    const auto bytes = Stream.TryReadSome(1);

    EXPECT_FALSE(appended);
    EXPECT_EQ(bytes, (std::vector<std::uint8_t>{7}));
}

TEST_F(Given_VpnCallbackStream, When_InputPrecedesHandoff_Then_DoesNotMixWithAuthentication)
{
    const std::array<std::uint8_t, 1> bytes{1};

    const bool appended = Stream.AppendInput(bytes);

    EXPECT_FALSE(appended);
}

TEST_F(Given_VpnCallbackStream, When_ReadIsSmallerThanCallback_Then_RetainsRemainingBytes)
{
    Stream.UseCallbackInput();
    const std::array<std::uint8_t, 3> input{1, 2, 3};
    ASSERT_TRUE(Stream.AppendInput(input));

    const auto first = Stream.TryReadSome(1);
    const bool remaining = Stream.HasBufferedInput();
    const auto second = Stream.TryReadSome(2);

    EXPECT_EQ(first, (std::vector<std::uint8_t>{1}));
    EXPECT_TRUE(remaining);
    EXPECT_EQ(second, (std::vector<std::uint8_t>{2, 3}));
    EXPECT_FALSE(Stream.HasBufferedInput());
}

} // namespace
} // namespace tailgate::uwp::tests
