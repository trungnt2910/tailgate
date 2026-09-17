#include <array>
#include <chrono>
#include <cstdint>
#include <limits>

#include <sys/socket.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "FdStream.h"
#include "UniqueFd.h"

class Given_FdStream : public testing::Test
{
protected:
    void SetUp() override
    {
        std::array<int, 2> sockets{};
        ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets.data()), 0);
        m_descriptor = tailgate::linux_frontend::UniqueFd(sockets[0]);
        m_peer = tailgate::linux_frontend::UniqueFd(sockets[1]);
    }

    tailgate::linux_frontend::UniqueFd m_descriptor;
    tailgate::linux_frontend::UniqueFd m_peer;
};

TEST_F(Given_FdStream, When_ReadBudgetIsUnboundedAndIdle_Then_ReadWouldBlock)
{
    tailgate::linux_frontend::FdStream stream(m_descriptor.Fd);

    const auto result = stream.TryReadSome(std::numeric_limits<std::size_t>::max());

    EXPECT_FALSE(result.has_value());
}

TEST_F(Given_FdStream, When_ReadBudgetIsUnboundedAndDataExists_Then_OnlyDataIsReturned)
{
    tailgate::linux_frontend::FdStream stream(m_descriptor.Fd);
    const std::vector<std::uint8_t> payload{1, 2, 3, 4};
    ASSERT_EQ(write(m_peer.Fd, payload.data(), payload.size()), 4);

    const auto result = stream.TryReadSome(std::numeric_limits<std::size_t>::max());

    EXPECT_EQ(result, payload);
}

TEST_F(Given_FdStream, When_ReadBudgetShrinks_Then_ReadsRespectBudgetAndOwnTheirData)
{
    tailgate::linux_frontend::FdStream stream(m_descriptor.Fd);
    const std::vector<std::uint8_t> payload{1, 2, 3, 4};
    constexpr std::size_t LargeBudget = 64U * 1024U;
    ASSERT_FALSE(stream.TryReadSome(LargeBudget).has_value());
    ASSERT_EQ(write(m_peer.Fd, payload.data(), payload.size()), 4);

    const auto first = stream.TryReadSome(1);
    const auto second = stream.TryReadSome(3);
    const auto idle = stream.TryReadSome(1);

    EXPECT_EQ(first, (std::vector<std::uint8_t>{1}));
    EXPECT_EQ(second, (std::vector<std::uint8_t>{2, 3, 4}));
    EXPECT_FALSE(idle.has_value());
}

TEST_F(Given_FdStream, When_ClearedReadDeadlineHasData_Then_ReadSucceeds)
{
    tailgate::linux_frontend::FdStream stream(m_descriptor.Fd);
    stream.SetReadTimeout(std::chrono::milliseconds(1));
    stream.ClearReadTimeout();
    constexpr std::uint8_t Value = 42;

    const ssize_t written = write(m_peer.Fd, &Value, sizeof(Value));
    const std::vector<std::uint8_t> received = stream.ReadSome(1);

    EXPECT_EQ(written, 1);
    EXPECT_EQ(received, std::vector<std::uint8_t>{Value});
}

TEST_F(Given_FdStream, When_ReadDeadlineExpiresOnSilentDescriptor_Then_ReadFails)
{
    tailgate::linux_frontend::FdStream stream(m_descriptor.Fd);
    stream.SetReadTimeout(std::chrono::milliseconds(1));

    const auto read = [&]()
    {
        (void)stream.ReadSome(1);
    };

    EXPECT_THROW(read(), std::runtime_error);
}
