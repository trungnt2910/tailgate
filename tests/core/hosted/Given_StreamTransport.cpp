#include <memory>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/hosted/StreamTransport.h>

#include "fakes/types/nettype/FakeTcpSocket.h"

namespace tailgate
{
namespace
{

class Given_StreamTransport : public testing::Test
{
protected:
    std::shared_ptr<tests::fakes::FakeTcpSocketState> State =
        std::make_shared<tests::fakes::FakeTcpSocketState>();
    hosted::StreamTransport Transport{std::make_unique<tests::fakes::FakeTcpSocket>(State), {}};
};

TEST_F(Given_StreamTransport, When_WriteBlocks_Then_QueuedBytesRetainOrderUntilCompletion)
{
    ASSERT_TRUE(Transport.Queue({1, 2, 3}));
    ASSERT_TRUE(Transport.Queue({4, 5}));
    State->WriteWouldBlock = true;

    const bool blockedWork = Transport.Flush(2);
    const bool interested = State->WriteInterest;
    State->WriteWouldBlock = false;
    const bool more = Transport.Flush(1);
    const auto first = State->Written;
    const bool completed = Transport.Flush(1);

    EXPECT_FALSE(blockedWork);
    EXPECT_TRUE(interested);
    EXPECT_TRUE(more);
    EXPECT_EQ(first, (std::vector<std::uint8_t>{1, 2, 3}));
    EXPECT_FALSE(completed);
    EXPECT_EQ(State->Written, (std::vector<std::uint8_t>{1, 2, 3, 4, 5}));
    EXPECT_FALSE(State->WriteInterest);
    EXPECT_TRUE(State->NonBlocking);
}

TEST_F(Given_StreamTransport, When_FrameBatchLimitIsReached_Then_BufferedFramesNeedAnotherTurn)
{
    const auto first = hosted::Frame(hosted::MessageType::Heartbeat, {1}).Encode();
    const auto second = hosted::Frame(hosted::MessageType::Heartbeat, {2}).Encode();
    auto bytes = first;
    bytes.insert(bytes.end(), second.begin(), second.end());
    State->Incoming.push_back(bytes);

    const auto batch = Transport.Receive(1, 1);
    const bool more = Transport.HasBufferedInput();
    const auto next = Transport.Receive(1, 4);

    EXPECT_EQ(batch.size(), 1U);
    EXPECT_EQ(batch.at(0).Payload(), (std::vector<std::uint8_t>{1}));
    EXPECT_TRUE(more);
    EXPECT_EQ(next.size(), 1U);
    EXPECT_EQ(next.at(0).Payload(), (std::vector<std::uint8_t>{2}));
    EXPECT_FALSE(Transport.HasBufferedInput());
}

TEST_F(Given_StreamTransport, When_FrameIsSplitAcrossReads_Then_DecoderRetainsItsPrefix)
{
    const auto frame = hosted::Frame(hosted::MessageType::Heartbeat, {1, 2}).Encode();
    State->Incoming.push_back(std::vector<std::uint8_t>(frame.begin(), frame.begin() + 2));

    const auto first = Transport.Receive(1, 4);
    State->Incoming.push_back(std::vector<std::uint8_t>(frame.begin() + 2, frame.end()));
    const auto second = Transport.Receive(1, 4);
    const bool more = Transport.HasBufferedInput();
    const auto drained = Transport.Receive(1, 4);

    EXPECT_TRUE(first.empty());
    EXPECT_EQ(second.size(), 1U);
    EXPECT_EQ(second.at(0).Payload(), (std::vector<std::uint8_t>{1, 2}));
    EXPECT_TRUE(more);
    EXPECT_TRUE(drained.empty());
    EXPECT_FALSE(Transport.HasBufferedInput());
}

TEST_F(Given_StreamTransport, When_PeerCloses_Then_ReadReportsFailure)
{
    State->Closed = true;

    EXPECT_THROW((void)Transport.Receive(1, 4), std::system_error);
}

TEST_F(Given_StreamTransport, When_QueueLimitIsReached_Then_NextWriteIsRejectedWithoutReordering)
{
    constexpr std::size_t Capacity = 4U * 1024U * 1024U;
    ASSERT_TRUE(Transport.Queue(std::vector<std::uint8_t>(Capacity, 7)));

    const bool rejected = Transport.Queue({8});
    const bool more = Transport.Flush(1);
    const bool accepted = Transport.Queue({9});
    (void)Transport.Flush(1);

    EXPECT_FALSE(rejected);
    EXPECT_FALSE(more);
    EXPECT_TRUE(accepted);
    EXPECT_EQ(State->Written.size(), Capacity + 1);
    EXPECT_EQ(State->Written.back(), 9);
}

TEST_F(Given_StreamTransport, When_HandshakeAlreadyBufferedFrames_Then_NoNewReadIsRequired)
{
    auto state = std::make_shared<tests::fakes::FakeTcpSocketState>();
    hosted::Decoder decoder;
    decoder.Feed(hosted::Frame(hosted::MessageType::Heartbeat, {5}).Encode());
    hosted::StreamTransport transport(std::make_unique<tests::fakes::FakeTcpSocket>(state),
                                      std::move(decoder));

    const auto frames = transport.Receive(0, 4);

    EXPECT_EQ(frames.size(), 1U);
    EXPECT_EQ(frames.at(0).Payload(), (std::vector<std::uint8_t>{5}));
}

TEST_F(Given_StreamTransport, When_WritesArePartial_Then_UnsentSuffixPrecedesNextPacket)
{
    State->MaximumWriteSize = 2;
    ASSERT_TRUE(Transport.Queue({1, 2, 3}));
    ASSERT_TRUE(Transport.Queue({4, 5}));

    const bool more = Transport.Flush(1);
    const auto first = State->Written;
    const bool finished = Transport.Flush(2);

    EXPECT_TRUE(more);
    EXPECT_EQ(first, (std::vector<std::uint8_t>{1, 2}));
    EXPECT_FALSE(finished);
    EXPECT_EQ(State->Written, (std::vector<std::uint8_t>{1, 2, 3, 4, 5}));
}

TEST_F(Given_StreamTransport, When_TlsWriteNeedsRead_Then_WritableInterestIsDisabled)
{
    State->WriteWouldBlock = true;
    State->WriteNeedsRead = true;
    State->Incoming.push_back(hosted::Frame(hosted::MessageType::Heartbeat, {1}).Encode());
    ASSERT_TRUE(Transport.Queue({1, 2}));

    const bool more = Transport.Flush(1);
    const auto frames = Transport.Receive(1, 4);

    EXPECT_FALSE(more);
    EXPECT_FALSE(State->WriteInterest);
    EXPECT_TRUE(frames.empty());
    EXPECT_EQ(State->Incoming.size(), 1U);
    EXPECT_FALSE(Transport.HasBufferedInput());
}

TEST_F(Given_StreamTransport, When_TlsReadNeedsWrite_Then_PendingReadPrecedesNewWrites)
{
    State->ReadNeedsWrite = true;
    ASSERT_TRUE(Transport.Queue({1, 2}));

    const auto frames = Transport.Receive(1, 4);
    const bool more = Transport.Flush(1);
    const bool interested = State->WriteInterest;
    const auto before = State->Written;
    State->ReadNeedsWrite = false;
    const bool completed = Transport.Flush(1);

    EXPECT_TRUE(frames.empty());
    EXPECT_FALSE(more);
    EXPECT_TRUE(interested);
    EXPECT_TRUE(before.empty());
    EXPECT_FALSE(completed);
    EXPECT_EQ(State->Written, (std::vector<std::uint8_t>{1, 2}));
}

TEST_F(Given_StreamTransport, When_PeerClosesAfterFrame_Then_FrameIsDeliveredBeforeDisconnect)
{
    State->Incoming.push_back(hosted::Frame(hosted::MessageType::Heartbeat, {3}).Encode());
    State->Incoming.push_back({});

    const auto frames = Transport.Receive(2, 4);

    EXPECT_EQ(frames.size(), 1U);
    EXPECT_EQ(frames.at(0).Payload(), (std::vector<std::uint8_t>{3}));
    EXPECT_TRUE(Transport.HasBufferedInput());
    EXPECT_THROW((void)Transport.Receive(1, 4), std::system_error);
}

} // namespace

} // namespace tailgate
