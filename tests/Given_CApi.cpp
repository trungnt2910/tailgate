#include <gtest/gtest.h>

#include "tailgate/c/tailgate.h"

#include <algorithm>
#include <array>
#include <vector>

namespace
{

struct AsyncStreamContext
{
    bool Writable = false;
    std::vector<std::uint8_t> Written;
};

tg_stream_result TryWrite(void* context, const std::uint8_t* data, size_t size, size_t* written)
{
    auto& stream = *static_cast<AsyncStreamContext*>(context);
    if (!stream.Writable)
    {
        return TG_STREAM_WOULD_BLOCK;
    }
    stream.Written.insert(stream.Written.end(), data, data + size);
    *written = size;
    return TG_STREAM_READY;
}

tg_stream_result TryRead(void*, std::uint8_t*, size_t, size_t*)
{
    return TG_STREAM_WOULD_BLOCK;
}

} // namespace

TEST(Given_CDiscoApi, When_Pinging_Then_PortableHandlesRoundTrip)
{
    std::array<uint8_t, 32> privateA{};
    std::array<uint8_t, 32> privateB{};
    std::array<uint8_t, 32> nodeA{};
    std::array<uint8_t, 32> nodeB{};
    ASSERT_TRUE(tg_generate_private_key(privateA.data()) == 0);
    ASSERT_TRUE(tg_generate_private_key(privateB.data()) == 0);
    ASSERT_TRUE(tg_generate_private_key(nodeA.data()) == 0);
    ASSERT_TRUE(tg_generate_private_key(nodeB.data()) == 0);

    tg_disco* a = tg_disco_create(privateA.data(), nodeA.data());
    tg_disco* b = tg_disco_create(privateB.data(), nodeB.data());
    ASSERT_TRUE(a != nullptr);
    ASSERT_TRUE(b != nullptr);

    std::array<uint8_t, 32> publicB{};
    std::array<uint8_t, 12> transaction{};
    ASSERT_TRUE(tg_disco_public_key(b, publicB.data()) == 0);
    ASSERT_TRUE(tg_disco_new_transaction(a, transaction.data()) == 0);
    tg_buffer packet{};

    ASSERT_TRUE(tg_disco_build_ping(a, publicB.data(), transaction.data(), &packet) == 0);

    tg_disco_message message{};
    ASSERT_TRUE(tg_disco_parse(b, packet.data, packet.size, &message) == 0);

    ASSERT_TRUE(message.type == TG_DISCO_PING);
    ASSERT_TRUE(std::equal(transaction.begin(), transaction.end(), message.transaction_id));

    tg_buffer_free(packet);
    tg_disco_destroy(a);
    tg_disco_destroy(b);
}

TEST(Given_AsyncCStreamWouldBlock, When_DerpSends_Then_OutputRemainsQueuedUntilFlush)
{
    AsyncStreamContext stream;
    std::array<std::uint8_t, 32> privateKey{};
    std::array<std::uint8_t, 32> publicKey{};
    std::array<std::uint8_t, 32> destination{};
    tg_derp* derp =
        tg_derp_create({&stream, TryWrite, TryRead}, privateKey.data(), publicKey.data());
    ASSERT_NE(derp, nullptr);

    const int sendResult = tg_derp_send(derp, destination.data(), nullptr, 0);

    EXPECT_EQ(sendResult, 0);
    EXPECT_EQ(tg_derp_has_pending_output(derp), 1);
    EXPECT_TRUE(stream.Written.empty());

    stream.Writable = true;
    const int flushResult = tg_derp_flush(derp);

    EXPECT_EQ(flushResult, 0);
    EXPECT_EQ(tg_derp_has_pending_output(derp), 0);
    EXPECT_FALSE(stream.Written.empty());

    tg_derp_destroy(derp);
}
