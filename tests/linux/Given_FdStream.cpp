#include <array>
#include <chrono>
#include <cstdint>

#include <sys/socket.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "FdStream.h"

TEST(Given_FdStream, When_ClearedReadDeadlineHasData_Then_ReadSucceeds)
{
    std::array<int, 2> sockets{};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()), 0);
    tailgate::linux_frontend::FdStream stream(sockets[0]);
    stream.SetReadTimeout(std::chrono::milliseconds(1));
    stream.ClearReadTimeout();
    constexpr std::uint8_t Value = 42;

    const ssize_t written = write(sockets[1], &Value, sizeof(Value));
    const std::vector<std::uint8_t> received = stream.ReadSome(1);
    close(sockets[0]);
    close(sockets[1]);

    EXPECT_EQ(written, 1);
    EXPECT_EQ(received, std::vector<std::uint8_t>{Value});
}

TEST(Given_FdStream, When_ReadDeadlineExpiresOnSilentDescriptor_Then_ReadFails)
{
    std::array<int, 2> sockets{};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()), 0);
    tailgate::linux_frontend::FdStream stream(sockets[0]);
    stream.SetReadTimeout(std::chrono::milliseconds(1));
    const auto read = [&]()
    {
        (void)stream.ReadSome(1);
    };

    EXPECT_THROW(read(), std::runtime_error);

    close(sockets[0]);
    close(sockets[1]);
}
