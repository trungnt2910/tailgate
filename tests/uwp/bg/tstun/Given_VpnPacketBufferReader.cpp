#include <algorithm>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include "VpnPacketBufferReader.h"

#include "fakes/bg/tstun/FakeVpnPacketBuffer.h"
#include "fakes/bg/tstun/FakeVpnPacketBufferList.h"

namespace tailgate::uwp::tests
{
namespace
{
namespace vpn = winrt::Windows::Networking::Vpn;

class Given_VpnPacketBufferReader : public testing::Test
{
protected:
    const vpn::VpnPacketBufferList Input =
        winrt::make<FakeVpnPacketBufferList>().as<vpn::VpnPacketBufferList>();
    const vpn::VpnPacketBufferList Output =
        winrt::make<FakeVpnPacketBufferList>().as<vpn::VpnPacketBufferList>();
    const std::vector<std::uint8_t> Payload{0x45, 1, 2, 3, 4, 5};
    const vpn::VpnPacketBuffer Packet =
        winrt::make<FakeVpnPacketBuffer>(Payload).as<vpn::VpnPacketBuffer>();
};

TEST_F(Given_VpnPacketBufferReader,
       When_PacketIsRead_Then_ReturnsOriginalBytesAndRecyclesBufferThroughOutput)
{
    Input.Append(Packet);

    const auto bytes = bg::VpnPacketBufferReader::Read(Input, Output);
    ASSERT_EQ(Output.Size(), 1U);
    const auto recycled = Output.RemoveAtBegin();
    const auto buffer = recycled.Buffer();

    EXPECT_EQ(bytes, Payload);
    EXPECT_EQ(Input.Size(), 0U);
    EXPECT_EQ(recycled, Packet);
    EXPECT_EQ(buffer.Length(), 1U);
    EXPECT_EQ(buffer.data()[0], 0);
}

TEST_F(Given_VpnPacketBufferReader, When_PoolBufferIsReusedRepeatedly_Then_EverySendReturnsIt)
{
    constexpr std::size_t PacketCount = 2048;
    auto recycled = Packet;
    std::size_t returned = 0;
    bool payloadsPreserved = true;

    for (std::size_t index = 0; index < PacketCount; ++index)
    {
        auto buffer = recycled.Buffer();
        std::ranges::copy(Payload, buffer.data());
        buffer.Length(static_cast<std::uint32_t>(Payload.size()));
        Input.Append(recycled);
        const auto bytes = bg::VpnPacketBufferReader::Read(Input, Output);
        ASSERT_EQ(Output.Size(), 1U);
        recycled = Output.RemoveAtBegin();
        payloadsPreserved &= bytes == Payload && recycled.Buffer().Length() == 1;
        ++returned;
    }

    EXPECT_EQ(returned, PacketCount);
    EXPECT_TRUE(payloadsPreserved);
    EXPECT_EQ(Input.Size(), 0U);
    EXPECT_EQ(Output.Size(), 0U);
    EXPECT_EQ(recycled, Packet);
}

} // namespace
} // namespace tailgate::uwp::tests
