#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/base/EventLoop.h>
#include <tailgate/wgengine/tstun/Device.h>

#include "PacketDevice.h"

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
    tailgate::uwp::bg::PacketDevice subject;
    ASSERT_TRUE(subject.Open(DeviceOptions()));
    const std::vector<std::uint8_t> packet{1, 2, 3, 4};
    ASSERT_EQ(subject.QueueInput(packet), tailgate::uwp::bg::PacketQueueResult::Complete);

    const tailgate::wgengine::tstun::DeviceReadResult result = subject.TryRead(packet.size());

    EXPECT_EQ(result.Result, tailgate::wgengine::tstun::DeviceIoResult::Complete);
    EXPECT_EQ(result.Packet, packet);
}

TEST(Given_PacketDevice, When_CoreWritesPacket_Then_PlatformCanDrainIt)
{
    tailgate::uwp::bg::PacketDevice subject;
    ASSERT_TRUE(subject.Open(DeviceOptions()));
    const std::vector<std::uint8_t> packet{5, 6, 7, 8};

    const tailgate::wgengine::tstun::DeviceIoResult writeResult = subject.TryWrite(packet);
    const std::vector<std::vector<std::uint8_t>> packets = subject.DrainOutput();

    ASSERT_EQ(packets.size(), 1U);
    EXPECT_EQ(writeResult, tailgate::wgengine::tstun::DeviceIoResult::Complete);
    EXPECT_EQ(packets.front(), packet);
}

TEST(Given_PacketDevice, When_Closed_Then_PacketQueuesRejectInputAndOutput)
{
    tailgate::uwp::bg::PacketDevice subject;
    ASSERT_TRUE(subject.Open(DeviceOptions()));
    subject.Close();
    const std::vector<std::uint8_t> packet{9};

    const tailgate::uwp::bg::PacketQueueResult inputResult = subject.QueueInput(packet);
    const tailgate::wgengine::tstun::DeviceIoResult outputResult = subject.TryWrite(packet);

    EXPECT_EQ(inputResult, tailgate::uwp::bg::PacketQueueResult::Closed);
    EXPECT_EQ(outputResult, tailgate::wgengine::tstun::DeviceIoResult::Closed);
}

TEST(Given_PacketDevice, When_TransportIsNotPrepared_Then_OpenIsRejected)
{
    tailgate::uwp::bg::PacketDevice subject;
    const tailgate::types::nettype::TcpSocketOptions options;

    const auto open = [&]()
    {
        (void)subject.OpenTransportSocket(options);
    };

    EXPECT_THROW(open(), std::logic_error);
}
