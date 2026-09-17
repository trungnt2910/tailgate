#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <gtest/gtest.h>

#include <tailgate/net/tls/TlsStream.h>

#include "core/fakes/crypto/TestCertificates.h"
#include "support/BufferedByteStream.h"

#include "FdStream.h"
#include "PeerApiServer.h"
#include "UniqueFd.h"

namespace
{

using tailgate::linux_frontend::FdStream;
using tailgate::linux_frontend::UniqueFd;

constexpr std::chrono::seconds SocketTimeout{20};

class IgnoreSigpipe final
{
public:
    IgnoreSigpipe() : m_previous(std::signal(SIGPIPE, SIG_IGN))
    {
        if (m_previous == SIG_ERR)
        {
            throw std::system_error(errno, std::generic_category());
        }
    }

    ~IgnoreSigpipe()
    {
        std::signal(SIGPIPE, m_previous);
    }

private:
    using Handler = void (*)(int);
    Handler m_previous;
};

UniqueFd OpenSocket()
{
    UniqueFd socket(::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (socket.Fd < 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    const timeval timeout{.tv_sec = SocketTimeout.count(), .tv_usec = 0};
    if (setsockopt(socket.Fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0 ||
        setsockopt(socket.Fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) != 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    return socket;
}

sockaddr_in LoopbackAddress(std::uint16_t port = 0)
{
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    return address;
}

UniqueFd BindLoopbackSocket()
{
    UniqueFd socket = OpenSocket();
    const int reuse = 1;
    const sockaddr_in address = LoopbackAddress();
    if (setsockopt(socket.Fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) != 0 ||
        bind(socket.Fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    return socket;
}

std::uint16_t BoundPort(int fd)
{
    sockaddr_in address{};
    socklen_t size = sizeof(address);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) != 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    return ntohs(address.sin_port);
}

std::vector<std::uint8_t> Bytes(std::string_view text)
{
    return {text.begin(), text.end()};
}

std::vector<std::uint8_t> ReadUntilClosed(tailgate::base::ByteStream& stream)
{
    constexpr std::size_t ReadSize = 1024;
    std::vector<std::uint8_t> result;
    for (auto part = stream.ReadSome(ReadSize); !part.empty(); part = stream.ReadSome(ReadSize))
    {
        result.insert(result.end(), part.begin(), part.end());
    }
    return result;
}

struct IngressConnection final
{
    explicit IngressConnection(int receiveBufferSize = 0)
    {
        auto originListener = BindLoopbackSocket();
        if (listen(originListener.Fd, 1) != 0)
        {
            throw std::system_error(errno, std::generic_category());
        }
        // Both sockets use SO_REUSEADDR. Keep the non-listening reservation bound
        // until PeerApiServer owns the listener, without a free-port allocation gap.
        auto ingressReservation = BindLoopbackSocket();
        const auto ingressPort = BoundPort(ingressReservation.Fd);
        Server = std::make_unique<tailgate::linux_frontend::PeerApiServer>(
            "127.0.0.1",
            ingressPort,
            "node.example.ts.net:10000",
            BoundPort(originListener.Fd),
            std::string(tailgate::tests::fakes::IngressCertificate),
            std::string(tailgate::tests::fakes::IngressPrivateKey));
        PeerSocket = OpenSocket();
        if (receiveBufferSize != 0 && setsockopt(PeerSocket.Fd,
                                                 SOL_SOCKET,
                                                 SO_RCVBUF,
                                                 &receiveBufferSize,
                                                 sizeof(receiveBufferSize)) != 0)
        {
            throw std::system_error(errno, std::generic_category());
        }
        const sockaddr_in ingressAddress = LoopbackAddress(ingressPort);
        if (connect(PeerSocket.Fd,
                    reinterpret_cast<const sockaddr*>(&ingressAddress),
                    sizeof(ingressAddress)) != 0)
        {
            throw std::system_error(errno, std::generic_category());
        }
        PeerTransport = std::make_unique<FdStream>(PeerSocket.Fd);
        PeerTransport->SetReadTimeout(SocketTimeout);
        PeerTransport->WriteAll(Bytes("POST /v0/ingress HTTP/1.1\r\n"
                                      "Host: peerapi\r\n"
                                      "Tailscale-Ingress-Src: 192.0.2.1:12345\r\n"
                                      "Tailscale-Ingress-Target: node.example.ts.net:10000\r\n"
                                      "\r\n"));
        const auto upgrade = Bytes("HTTP/1.1 101 Switching Protocols\r\n\r\n");
        Upgrade = PeerTransport->ReadExact(upgrade.size());
        Client = std::make_unique<tailgate::net::tls::TlsStream>(
            *PeerTransport,
            "node.example.ts.net",
            Bytes(tailgate::tests::fakes::IngressCertificate));
        OriginSocket = UniqueFd(accept4(originListener.Fd, nullptr, nullptr, SOCK_CLOEXEC));
        if (OriginSocket.Fd < 0)
        {
            throw std::system_error(errno, std::generic_category());
        }
        Origin = std::make_unique<FdStream>(OriginSocket.Fd);
        Origin->SetReadTimeout(SocketTimeout);
    }

    IgnoreSigpipe Sigpipe;
    std::unique_ptr<tailgate::linux_frontend::PeerApiServer> Server;
    UniqueFd PeerSocket;
    std::unique_ptr<FdStream> PeerTransport;
    std::unique_ptr<tailgate::net::tls::TlsStream> Client;
    UniqueFd OriginSocket;
    std::unique_ptr<FdStream> Origin;
    std::vector<std::uint8_t> Upgrade;
};

} // namespace

TEST(Given_PeerApiServer, When_OriginSendsResponseAndCloses_Then_FinalResponseIsForwarded)
{
    IngressConnection connection;
    ASSERT_EQ(connection.Upgrade, Bytes("HTTP/1.1 101 Switching Protocols\r\n\r\n"));
    ASSERT_TRUE(connection.Client->HandshakeComplete());
    const auto request = Bytes("GET / HTTP/1.0\r\n\r\n");
    const auto response = Bytes("HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nend");
    const int cork = 1;
    ASSERT_EQ(setsockopt(connection.OriginSocket.Fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork)),
              0);

    connection.Client->WriteAll(request);
    const auto receivedRequest = connection.Origin->ReadExact(request.size());
    connection.Origin->WriteAll(response);
    const int closed = shutdown(connection.OriginSocket.Fd, SHUT_WR);
    const auto receivedResponse = ReadUntilClosed(*connection.Client);

    EXPECT_EQ(receivedRequest, request);
    EXPECT_EQ(closed, 0);
    EXPECT_EQ(receivedResponse, response);
}

TEST(Given_PeerApiServer, When_ClientSendsRequestAndTlsClose_Then_FinalRequestIsForwarded)
{
    IngressConnection connection;
    ASSERT_EQ(connection.Upgrade, Bytes("HTTP/1.1 101 Switching Protocols\r\n\r\n"));
    ASSERT_TRUE(connection.Client->HandshakeComplete());
    const auto request = Bytes("POST / HTTP/1.0\r\nContent-Length: 3\r\n\r\nend");
    const int cork = 1;
    ASSERT_EQ(setsockopt(connection.PeerSocket.Fd, IPPROTO_TCP, TCP_CORK, &cork, sizeof(cork)), 0);

    connection.Client->WriteAll(request);
    connection.Client.reset();
    const int closed = shutdown(connection.PeerSocket.Fd, SHUT_WR);
    const auto receivedRequest = ReadUntilClosed(*connection.Origin);

    EXPECT_EQ(closed, 0);
    EXPECT_EQ(receivedRequest, request);
}

TEST(Given_PeerApiServer, When_LargeResponseClosesBeforeClientReads_Then_EntireResponseIsForwarded)
{
    constexpr int ReceiveBufferSize = 4096;
    constexpr std::size_t ResponseSize = 2U * 1024U * 1024U;
    IngressConnection connection(ReceiveBufferSize);
    ASSERT_EQ(connection.Upgrade, Bytes("HTTP/1.1 101 Switching Protocols\r\n\r\n"));
    ASSERT_TRUE(connection.Client->HandshakeComplete());
    const auto request = Bytes("GET / HTTP/1.0\r\n\r\n");
    const std::vector<std::uint8_t> response(ResponseSize, 'x');

    connection.Client->WriteAll(request);
    const auto receivedRequest = connection.Origin->ReadExact(request.size());
    connection.Origin->WriteAll(response);
    const int closed = shutdown(connection.OriginSocket.Fd, SHUT_WR);
    const auto receivedResponse = ReadUntilClosed(*connection.Client);

    EXPECT_EQ(receivedRequest, request);
    EXPECT_EQ(closed, 0);
    EXPECT_EQ(receivedResponse, response);
}

TEST(Given_PeerApiServer, When_NoTlsInputIsBuffered_Then_EventLoopWaitsForFd)
{
    tailgate::tests::support::BufferedByteStream stream(false);

    const int timeout = tailgate::linux_frontend::PeerApiWaitTimeout(stream);

    EXPECT_EQ(-1, timeout);
}

TEST(Given_PeerApiServer, When_TlsInputIsBuffered_Then_EventLoopDoesNotBlock)
{
    tailgate::tests::support::BufferedByteStream stream(true);

    const int timeout = tailgate::linux_frontend::PeerApiWaitTimeout(stream);

    EXPECT_EQ(0, timeout);
}

TEST(Given_PeerApiServer, When_TlsReadNeedsWrite_Then_EventLoopWaitsForFd)
{
    tailgate::tests::support::BufferedByteStream stream(true, true);

    const int timeout = tailgate::linux_frontend::PeerApiWaitTimeout(stream);

    EXPECT_EQ(-1, timeout);
}
