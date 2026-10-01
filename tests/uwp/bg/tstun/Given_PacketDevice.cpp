#include <cstdint>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/base/EventLoop.h>
#include <tailgate/wgengine/tstun/Device.h>

#include "PacketDevice.h"

#include "fakes/base/FakeEventLoop.h"

namespace
{

constexpr tailgate::base::EventToken ReadinessToken{.Value = 1};

tailgate::wgengine::tstun::DeviceOptions DeviceOptions()
{
    return tailgate::wgengine::tstun::DeviceOptions{
        .Name = {},
        .ReadinessToken = ReadinessToken,
    };
}

} // namespace

TEST(Given_PacketDevice, When_InputIsQueued_Then_CoreCanReadIt)
{
    tailgate::tests::fakes::FakeEventLoop events;
    tailgate::uwp::bg::PacketDevice subject(events);
    ASSERT_TRUE(subject.Open(DeviceOptions()));
    const std::vector<std::uint8_t> packet{1, 2, 3, 4};
    ASSERT_EQ(subject.QueueInput(packet), tailgate::uwp::bg::PacketQueueResult::Complete);

    const tailgate::wgengine::tstun::DeviceReadResult result = subject.TryRead(packet.size());

    EXPECT_EQ(result.Result, tailgate::wgengine::tstun::DeviceIoResult::Complete);
    EXPECT_EQ(result.Packet, packet);
}

TEST(Given_PacketDevice, When_CoreWritesPacket_Then_PlatformCanDrainIt)
{
    tailgate::tests::fakes::FakeEventLoop events;
    tailgate::uwp::bg::PacketDevice subject(events);
    ASSERT_TRUE(subject.Open(DeviceOptions()));
    const std::vector<std::uint8_t> packet{5, 6, 7, 8};

    const tailgate::wgengine::tstun::DeviceIoResult writeResult = subject.TryWrite(packet);
    const bool pending = subject.HasOutput();
    const std::vector<std::vector<std::uint8_t>> packets = subject.DrainOutput();
    ASSERT_EQ(packets.size(), 1U);

    EXPECT_EQ(writeResult, tailgate::wgengine::tstun::DeviceIoResult::Complete);
    EXPECT_EQ(packets.at(0), packet);
    EXPECT_TRUE(pending);
    EXPECT_FALSE(subject.HasOutput());
}

TEST(Given_PacketDevice, When_Closed_Then_PacketQueuesRejectInputAndOutput)
{
    tailgate::tests::fakes::FakeEventLoop events;
    tailgate::uwp::bg::PacketDevice subject(events);
    ASSERT_TRUE(subject.Open(DeviceOptions()));
    subject.Close();
    const std::vector<std::uint8_t> packet{9};

    const tailgate::uwp::bg::PacketQueueResult inputResult = subject.QueueInput(packet);
    const tailgate::wgengine::tstun::DeviceIoResult outputResult = subject.TryWrite(packet);

    EXPECT_EQ(inputResult, tailgate::uwp::bg::PacketQueueResult::Closed);
    EXPECT_EQ(outputResult, tailgate::wgengine::tstun::DeviceIoResult::Closed);
}

TEST(Given_PacketDevice, When_ReadBatchLeavesPackets_Then_ReadinessIsRetained)
{
    tailgate::tests::fakes::FakeEventLoop events;
    tailgate::uwp::bg::PacketDevice subject(events);
    ASSERT_TRUE(subject.Open(DeviceOptions()));
    ASSERT_EQ(subject.QueueInput({1}), tailgate::uwp::bg::PacketQueueResult::Complete);
    ASSERT_EQ(subject.QueueInput({2}), tailgate::uwp::bg::PacketQueueResult::Complete);
    ASSERT_FALSE(events.TakePostedEvents(8).empty());

    const auto first = subject.TryRead(1);
    const auto ready = events.TakePostedEvents(8);
    const auto second = subject.TryRead(1);
    const auto drained = events.TakePostedEvents(8);

    EXPECT_EQ(first.Packet, (std::vector<std::uint8_t>{1}));
    EXPECT_EQ(second.Packet, (std::vector<std::uint8_t>{2}));
    EXPECT_EQ(ready.size(), 1U);
    EXPECT_EQ(ready.at(0).Token, ReadinessToken);
    EXPECT_EQ(ready.at(0).Readiness, tailgate::base::EventReadiness::Readable);
    EXPECT_TRUE(drained.empty());
}

TEST(Given_PacketDevice, When_FullOutputIsDrained_Then_BlockedWriterIsWoken)
{
    tailgate::tests::fakes::FakeEventLoop events;
    tailgate::uwp::bg::PacketDevice subject(events);
    ASSERT_TRUE(subject.Open(DeviceOptions()));
    constexpr std::size_t PacketLimit = 1024;
    for (std::size_t index = 0; index < PacketLimit; ++index)
    {
        ASSERT_EQ(subject.TryWrite({1}), tailgate::wgengine::tstun::DeviceIoResult::Complete);
    }

    const auto blocked = subject.TryWrite({2});
    subject.SetWriteInterest(true);
    const auto before = events.TakePostedEvents(8);
    const auto output = subject.DrainOutput();
    const auto ready = events.TakePostedEvents(8);
    const auto empty = subject.DrainOutput();
    const auto after = events.TakePostedEvents(8);

    EXPECT_EQ(blocked, tailgate::wgengine::tstun::DeviceIoResult::WouldBlock);
    EXPECT_TRUE(before.empty());
    EXPECT_EQ(output.size(), PacketLimit);
    EXPECT_EQ(ready.size(), 1U);
    EXPECT_EQ(ready.at(0).Token, ReadinessToken);
    EXPECT_EQ(ready.at(0).Readiness, tailgate::base::EventReadiness::Writable);
    EXPECT_TRUE(empty.empty());
    EXPECT_TRUE(after.empty());
}

TEST(Given_PacketDevice, When_WriteInterestIsUnchanged_Then_NoRepeatedWakeIsPosted)
{
    tailgate::tests::fakes::FakeEventLoop events;
    tailgate::uwp::bg::PacketDevice subject(events);
    ASSERT_TRUE(subject.Open(DeviceOptions()));
    subject.SetWriteInterest(true);

    const auto first = events.TakePostedEvents(8);
    subject.SetWriteInterest(true);
    const auto repeated = events.TakePostedEvents(8);

    EXPECT_EQ(first.size(), 1U);
    EXPECT_EQ(first.at(0).Readiness, tailgate::base::EventReadiness::Writable);
    EXPECT_TRUE(repeated.empty());
}

TEST(Given_PacketDevice, When_PacketExceedsReadLimit_Then_ErrorDoesNotTruncateTheNextPacket)
{
    tailgate::tests::fakes::FakeEventLoop events;
    tailgate::uwp::bg::PacketDevice subject(events);
    ASSERT_TRUE(subject.Open(DeviceOptions()));
    ASSERT_EQ(subject.QueueInput({1, 2}), tailgate::uwp::bg::PacketQueueResult::Complete);
    ASSERT_EQ(subject.QueueInput({3}), tailgate::uwp::bg::PacketQueueResult::Complete);
    std::error_code error;

    try
    {
        (void)subject.TryRead(1);
    }
    catch (const std::system_error& failure)
    {
        error = failure.code();
    }
    const auto next = subject.TryRead(1);

    EXPECT_EQ(error, std::errc::message_size);
    EXPECT_EQ(next.Result, tailgate::wgengine::tstun::DeviceIoResult::Complete);
    EXPECT_EQ(next.Packet, (std::vector<std::uint8_t>{3}));
}
