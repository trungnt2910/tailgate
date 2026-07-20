#include "FdStream.h"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstdint>

#include <sys/socket.h>
#include <unistd.h>

TEST(Given_SilentDescriptor, When_ReadDeadlineExpires_Then_ReadFails)
{
    std::array<int, 2> sockets{};
    EXPECT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()), 0);
    tailgate::linux_frontend::FdStream stream(sockets[0]);
    stream.SetReadTimeout(std::chrono::milliseconds(1));

    EXPECT_THROW((void)stream.ReadSome(1), std::runtime_error);

    close(sockets[0]);
    close(sockets[1]);
}

TEST(Given_ClearedReadDeadline, When_DataArrives_Then_ReadSucceeds)
{
    std::array<int, 2> sockets{};
    EXPECT_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()), 0);
    tailgate::linux_frontend::FdStream stream(sockets[0]);
    stream.SetReadTimeout(std::chrono::milliseconds(1));
    stream.ClearReadTimeout();
    constexpr std::uint8_t Value = 42;

    EXPECT_EQ(write(sockets[1], &Value, sizeof(Value)), 1);
    const std::vector<std::uint8_t> received = stream.ReadSome(1);

    EXPECT_EQ(received, std::vector<std::uint8_t>{Value});
    close(sockets[0]);
    close(sockets[1]);
}
