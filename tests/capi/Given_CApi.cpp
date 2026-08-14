#include <algorithm>
#include <array>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/c/tailgate.h>

namespace
{

struct OwnedBuffer
{
    ~OwnedBuffer()
    {
        tg_buffer_free(Value);
    }

    tg_buffer Value{};
};

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

    std::unique_ptr<tg_disco, decltype(&tg_disco_destroy)> a(
        tg_disco_create(privateA.data(), nodeA.data()), &tg_disco_destroy);
    std::unique_ptr<tg_disco, decltype(&tg_disco_destroy)> b(
        tg_disco_create(privateB.data(), nodeB.data()), &tg_disco_destroy);
    ASSERT_NE(a, nullptr);
    ASSERT_NE(b, nullptr);

    std::array<uint8_t, 32> publicB{};
    std::array<uint8_t, 12> transaction{};
    ASSERT_EQ(tg_disco_public_key(b.get(), publicB.data()), 0);
    ASSERT_EQ(tg_disco_new_transaction(a.get(), transaction.data()), 0);
    OwnedBuffer packet;

    ASSERT_EQ(tg_disco_build_ping(a.get(), publicB.data(), transaction.data(), &packet.Value), 0);

    tg_disco_message message{};
    ASSERT_EQ(tg_disco_parse(b.get(), packet.Value.data, packet.Value.size, &message), 0);

    EXPECT_EQ(message.type, TG_DISCO_PING);
    EXPECT_TRUE(std::equal(transaction.begin(), transaction.end(), message.transaction_id));
}

TEST(Given_AsyncCStreamWouldBlock, When_DerpSends_Then_OutputRemainsQueuedUntilFlush)
{
    AsyncStreamContext stream;
    std::array<std::uint8_t, 32> privateKey{};
    std::array<std::uint8_t, 32> publicKey{};
    std::array<std::uint8_t, 32> destination{};
    std::unique_ptr<tg_derp, decltype(&tg_derp_destroy)> derp(
        tg_derp_create({&stream, TryWrite, TryRead}, privateKey.data(), publicKey.data()),
        &tg_derp_destroy);
    ASSERT_NE(derp, nullptr);

    const int sendResult = tg_derp_send(derp.get(), destination.data(), nullptr, 0);

    EXPECT_EQ(sendResult, 0);
    EXPECT_EQ(tg_derp_has_pending_output(derp.get()), 1);
    EXPECT_TRUE(stream.Written.empty());

    stream.Writable = true;
    const int flushResult = tg_derp_flush(derp.get());

    EXPECT_EQ(flushResult, 0);
    EXPECT_EQ(tg_derp_has_pending_output(derp.get()), 0);
    EXPECT_FALSE(stream.Written.empty());
}
