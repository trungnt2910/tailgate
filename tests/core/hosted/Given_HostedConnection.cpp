#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/base/ByteStream.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/hosted/Connection.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/types/nettype/TcpSocket.h>

#include "fakes/hosted/FakeTcpSocket.h"

namespace
{

using tailgate::tests::fakes::hosted::FakeTcpSocketFactory;

tailgate::hosted::ConnectionOptions MakeOptions()
{
    const tailgate::crypto::Bytes32 privateKey = tailgate::crypto::GeneratePrivateKey();
    tailgate::types::netmap::NetworkConfig network;
    network.Domain("example.ts.net");
    network.SelfNodeId(42);
    return tailgate::hosted::ConnectionOptions{
        .Socket =
            tailgate::types::nettype::TcpSocketOptions{
                .ConnectAddress = "relay.example.ts.net",
                .Service = "443",
                .NetworkInterface = std::nullopt,
                .TlsServerName = "relay.example.ts.net",
                .IoTimeout = std::chrono::seconds(20),
                .ConnectTimeout = std::nullopt,
                .ReadinessToken = {},
                .AllowTls13 = true,
                .NonBlockingAfterConnect = false,
            },
        .HttpHost = "relay.example.ts.net:443",
        .Hostname = "client",
        .OperatingSystem = "TestOS",
        .OperatingSystemVersion = "1.0",
        .Client =
            tailgate::hosted::ClientConfig{
                .NodePrivateKey = privateKey,
                .NodePublicKey = tailgate::crypto::X25519PublicFromPrivate(privateKey),
                .DiscoPrivateKey = tailgate::crypto::GeneratePrivateKey(),
                .Network = std::move(network),
                .ExitNode = {},
            },
    };
}

TEST(Given_HostedConnection, When_ServerProofIsValid_Then_AuthenticatedSessionIsReturned)
{
    const tailgate::crypto::Bytes32 relayPrivateKey = tailgate::crypto::GeneratePrivateKey();
    FakeTcpSocketFactory factory(relayPrivateKey, tailgate::crypto::GeneratePrivateKey(), false);
    tailgate::wgengine::PeerProtocol clientProtocol;
    tailgate::hosted::Client client{clientProtocol};
    tailgate::hosted::Connection subject(factory);
    const tailgate::hosted::ConnectionOptions options = MakeOptions();

    const tailgate::hosted::ConnectionResult result = subject.Connect(options);
    const auto& stream =
        dynamic_cast<const tailgate::tests::fakes::hosted::FakeTcpSocket&>(*result.Stream);
    const std::string output(stream.WrittenBytes().begin(), stream.WrittenBytes().end());

    EXPECT_EQ(result.RelayPublicKey, tailgate::crypto::X25519PublicFromPrivate(relayPrivateKey));
    EXPECT_EQ(result.RelaySession.Tailnet(), options.Client.Network.Domain());
    EXPECT_NE(output.find("Host: relay.example.ts.net:443"), std::string::npos);
    EXPECT_EQ(factory.Options->ConnectAddress, "relay.example.ts.net");
}

TEST(Given_HostedConnection,
     When_EventDrivenSessionIsRequested_Then_OnlyHandshakeRunsBeforeOwnerActivatesPath)
{
    FakeTcpSocketFactory factory(
        tailgate::crypto::GeneratePrivateKey(), tailgate::crypto::GeneratePrivateKey(), false);
    tailgate::wgengine::PeerProtocol clientProtocol;
    tailgate::hosted::Client client{clientProtocol};
    tailgate::hosted::Connection subject(factory);
    tailgate::hosted::ConnectionOptions options = MakeOptions();
    options.Socket.NonBlockingAfterConnect = true;

    const tailgate::hosted::ConnectionResult result = subject.Connect(options);
    const auto& stream =
        dynamic_cast<const tailgate::tests::fakes::hosted::FakeTcpSocket&>(*result.Stream);

    ASSERT_TRUE(factory.Options.has_value());
    EXPECT_FALSE(factory.Options->NonBlockingAfterConnect);
    EXPECT_TRUE(stream.IsNonBlocking());
    EXPECT_FALSE(client.Active());
    EXPECT_EQ(result.Configuration.Network.Domain(), options.Client.Network.Domain());
}

TEST(Given_HostedConnection, When_ServerRejectsAuthentication_Then_TypedReasonIsReturned)
{
    FakeTcpSocketFactory factory(
        tailgate::crypto::GeneratePrivateKey(), tailgate::crypto::GeneratePrivateKey(), true);
    tailgate::wgengine::PeerProtocol clientProtocol;
    tailgate::hosted::Client client{clientProtocol};
    tailgate::hosted::Connection subject(factory);
    std::optional<tailgate::hosted::ConnectionError> error;
    std::string reason;

    try
    {
        (void)subject.Connect(MakeOptions());
    }
    catch (const tailgate::hosted::ConnectionException& exception)
    {
        error = exception.Error();
        reason = exception.Reason();
    }

    EXPECT_EQ(error, tailgate::hosted::ConnectionError::Rejected);
    EXPECT_EQ(reason, "fake rejection");
}

} // namespace
