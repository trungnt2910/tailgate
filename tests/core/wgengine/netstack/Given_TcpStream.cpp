#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include <lwip/pbuf.h>
#include <lwip/tcp.h>

#include <tailgate/wgengine/netstack/Error.h>

#include "wgengine/netstack/impl/StreamImpl.h"

#include "fakes/di/FakeNetworkBindings.h"

namespace tailgate::tests
{
namespace netstack = wgengine::netstack;

class Given_TcpStream : public testing::Test
{
protected:
    Given_TcpStream()
    {
        fakes::InstallFakeNetworkBindings(injector);
        runtime = injector.create<std::shared_ptr<netstack::impl::Runtime>>();
        runtime->Start();
    }

    di::Injector injector;
    std::shared_ptr<netstack::impl::Runtime> runtime;
};

TEST_F(Given_TcpStream, When_ConnectionIsPending_Then_ReadAndWriteDoNotBlock)
{
    auto* pcb = tcp_new();
    ASSERT_NE(pcb, nullptr);
    netstack::impl::StreamImpl stream(runtime, pcb, netstack::StreamState::Connecting);
    const std::vector<std::uint8_t> bytes{1, 2, 3};

    const auto written = stream.TryWriteSome(bytes.data(), bytes.size());
    const auto read = stream.TryReadSome(bytes.size());

    EXPECT_FALSE(written.has_value());
    EXPECT_FALSE(read.has_value());
    EXPECT_EQ(stream.State(), netstack::StreamState::Connecting);
}

TEST_F(Given_TcpStream, When_RuntimeStops_Then_StreamCannotAccessFreedPcb)
{
    auto* pcb = tcp_new();
    ASSERT_NE(pcb, nullptr);
    netstack::impl::StreamImpl stream(runtime, pcb, netstack::StreamState::Connecting);

    runtime->Stop();
    const auto state = stream.State();
    const bool closed = stream.TryClose();

    EXPECT_EQ(state, netstack::StreamState::Failed);
    EXPECT_TRUE(closed);
    EXPECT_THROW((void)stream.TryReadSome(1), netstack::Exception);
    EXPECT_EQ(runtime->ConnectionCount(), 0U);
}

TEST_F(Given_TcpStream, When_CloseImmediatelyFreesPcb_Then_LaterCallsAreSafe)
{
    auto* pcb = tcp_new();
    ASSERT_NE(pcb, nullptr);
    netstack::impl::StreamImpl stream(runtime, pcb, netstack::StreamState::Connecting);

    const bool closed = stream.TryClose();
    const auto read = stream.TryReadSome(1);
    const auto state = stream.State();

    EXPECT_TRUE(closed);
    EXPECT_EQ(state, netstack::StreamState::Closed);
    EXPECT_EQ(read, std::vector<std::uint8_t>{});
    EXPECT_EQ(runtime->ConnectionCount(), 0U);
}

TEST_F(Given_TcpStream, When_ReceivedBufferIsPartiallyRead_Then_RemainderIsRetained)
{
    auto* pcb = tcp_new();
    ASSERT_NE(pcb, nullptr);
    netstack::impl::StreamImpl stream(runtime, pcb, netstack::StreamState::Connecting);
    const std::vector<std::uint8_t> bytes{1, 2, 3, 4};
    auto* packet = pbuf_alloc(PBUF_RAW, static_cast<std::uint16_t>(bytes.size()), PBUF_RAM);
    ASSERT_NE(packet, nullptr);
    ASSERT_EQ(pbuf_take(packet, bytes.data(), bytes.size()), ERR_OK);
    ASSERT_EQ(pcb->recv(pcb->callback_arg, pcb, packet, ERR_OK), ERR_OK);

    const auto first = stream.TryReadSome(2);
    const bool buffered = stream.HasBufferedInput();
    const auto second = stream.TryReadSome(2);
    const bool drained = !stream.HasBufferedInput();

    EXPECT_EQ(first, (std::vector<std::uint8_t>{1, 2}));
    EXPECT_TRUE(buffered);
    EXPECT_EQ(second, (std::vector<std::uint8_t>{3, 4}));
    EXPECT_TRUE(drained);
}

TEST_F(Given_TcpStream, When_PeerFinFollowsData_Then_BytesAreReadBeforeEof)
{
    auto* pcb = tcp_new();
    ASSERT_NE(pcb, nullptr);
    netstack::impl::StreamImpl stream(runtime, pcb, netstack::StreamState::Connecting);
    auto* packet = pbuf_alloc(PBUF_RAW, 1, PBUF_RAM);
    ASSERT_NE(packet, nullptr);
    const std::uint8_t value = 42;
    ASSERT_EQ(pbuf_take(packet, &value, sizeof(value)), ERR_OK);
    ASSERT_EQ(pcb->recv(pcb->callback_arg, pcb, packet, ERR_OK), ERR_OK);

    const auto accepted = pcb->recv(pcb->callback_arg, pcb, nullptr, ERR_OK);
    const auto bytes = stream.TryReadSome(1);
    const auto eof = stream.TryReadSome(1);

    EXPECT_EQ(accepted, ERR_OK);
    EXPECT_EQ(bytes, (std::vector<std::uint8_t>{value}));
    EXPECT_EQ(eof, std::vector<std::uint8_t>{});
}

} // namespace tailgate::tests
