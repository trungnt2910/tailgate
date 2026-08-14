#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/protocol/ControlHandshake.h>

#include "support/ScriptedByteStream.h"

namespace
{

tailgate::protocol::ControlHandshake Handshake()
{
    tailgate::protocol::Bytes32 machinePrivate{};
    tailgate::protocol::Bytes32 ephemeralPrivate{};
    machinePrivate[0] = 1;
    ephemeralPrivate[0] = 2;
    return tailgate::protocol::ControlHandshake(machinePrivate, ephemeralPrivate);
}

std::vector<std::uint8_t> Bytes(const char* text)
{
    const std::string value(text);
    return {value.begin(), value.end()};
}

} // namespace

TEST(Given_ControlHandshake, When_ServerRejectsUpgrade_Then_HandshakeFails)
{
    tailgate::test::ScriptedByteStream stream;
    stream.QueueRead(Bytes("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"));
    tailgate::protocol::ControlHandshake handshake = Handshake();
    const auto run = [&]()
    {
        (void)handshake.Run(stream, "controlplane.tailscale.com");
    };

    EXPECT_THROW(run(), std::runtime_error);
    EXPECT_FALSE(stream.Written.empty());
}

TEST(Given_ControlHandshake, When_NoResponseHeadersArrive_Then_HandshakeFails)
{
    tailgate::test::ScriptedByteStream stream;
    stream.QueueRead({});
    tailgate::protocol::ControlHandshake handshake = Handshake();
    const auto run = [&]()
    {
        (void)handshake.Run(stream, "controlplane.tailscale.com");
    };

    EXPECT_THROW(run(), std::runtime_error);
}

TEST(Given_ControlHandshake, When_NoiseMessageTypeIsUnexpected_Then_HandshakeFails)
{
    tailgate::test::ScriptedByteStream stream;
    std::vector<std::uint8_t> response =
        Bytes("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n");
    response.insert(response.end(), {0xff, 0, 0});
    stream.QueueRead(std::move(response));
    tailgate::protocol::ControlHandshake handshake = Handshake();
    const auto run = [&]()
    {
        (void)handshake.Run(stream, "controlplane.tailscale.com");
    };

    EXPECT_THROW(run(), std::runtime_error);
}
