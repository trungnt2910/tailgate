#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <system_error>
#include <utility>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <tailgate/base/EventLoop.h>
#include <tailgate/types/nettype/TcpSocket.h>

#include "UniqueFd.h"
#include "event/EventRegistry.h"
#include "impl/EventLoop.h"
#include "impl/TcpSocketFactory.h"
#include "impl/TimeProvider.h"

namespace
{

constexpr tailgate::base::EventToken TestToken{.Value = 42};
constexpr std::size_t MaximumEvents = 1;

struct ConnectedSocketPair
{
    std::unique_ptr<tailgate::types::nettype::TcpSocket> Client;
    tailgate::linux_frontend::UniqueFd Server;
};

ConnectedSocketPair Connect(tailgate::linux_frontend::impl::TcpSocketFactory& factory,
                            const tailgate::types::nettype::TcpSocketOptions& options)
{
    tailgate::linux_frontend::UniqueFd listener(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (listener.Fd < 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener.Fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
        listen(listener.Fd, 1) != 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    socklen_t addressLength = sizeof(address);
    if (getsockname(listener.Fd, reinterpret_cast<sockaddr*>(&address), &addressLength) != 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    tailgate::types::nettype::TcpSocketOptions connectedOptions = options;
    connectedOptions.ConnectAddress = "127.0.0.1";
    connectedOptions.Service = std::to_string(ntohs(address.sin_port));
    std::unique_ptr<tailgate::types::nettype::TcpSocket> client =
        factory.OpenTcpSocket(connectedOptions);
    tailgate::linux_frontend::UniqueFd server(accept4(listener.Fd, nullptr, nullptr, SOCK_CLOEXEC));
    if (server.Fd < 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    return ConnectedSocketPair{.Client = std::move(client), .Server = std::move(server)};
}

} // namespace

TEST(Given_LinuxTcpSocketFactory, When_BlockingSocketReceivesData_Then_EventLoopDoesNotObserveIt)
{
    auto registry = std::make_shared<tailgate::linux_frontend::event::EventRegistry>();
    tailgate::linux_frontend::impl::EventLoop loop(registry);
    tailgate::linux_frontend::impl::TimeProvider timeProvider;
    tailgate::linux_frontend::impl::TcpSocketFactory factory(registry);
    tailgate::types::nettype::TcpSocketOptions options;
    options.ReadinessToken = TestToken;
    options.NonBlockingAfterConnect = false;
    ConnectedSocketPair sockets = Connect(factory, options);
    constexpr std::uint8_t Byte = 1;
    ASSERT_EQ(send(sockets.Server.Fd, &Byte, sizeof(Byte), MSG_NOSIGNAL), sizeof(Byte));
    std::unique_ptr<tailgate::base::WaitToken> deadline =
        timeProvider.After(std::chrono::milliseconds(20));

    const tailgate::base::EventWaitResult result = loop.Wait(*deadline, MaximumEvents);

    EXPECT_EQ(result.Status, tailgate::base::EventWaitStatus::DeadlineReached);
    EXPECT_TRUE(result.Events.empty());
}

TEST(Given_LinuxTcpSocketFactory, When_BlockingSocketBecomesNonBlocking_Then_EventLoopObservesIt)
{
    auto registry = std::make_shared<tailgate::linux_frontend::event::EventRegistry>();
    tailgate::linux_frontend::impl::EventLoop loop(registry);
    tailgate::linux_frontend::impl::TcpSocketFactory factory(registry);
    tailgate::types::nettype::TcpSocketOptions options;
    options.ReadinessToken = TestToken;
    options.NonBlockingAfterConnect = false;
    ConnectedSocketPair sockets = Connect(factory, options);
    constexpr std::uint8_t Byte = 1;
    ASSERT_EQ(send(sockets.Server.Fd, &Byte, sizeof(Byte), MSG_NOSIGNAL), sizeof(Byte));

    sockets.Client->SetNonBlocking(true);
    const tailgate::base::EventWaitResult result = loop.Wait(MaximumEvents);

    ASSERT_EQ(result.Events.size(), 1U);
    EXPECT_EQ(result.Status, tailgate::base::EventWaitStatus::Events);
    EXPECT_EQ(result.Events.front().Token, TestToken);
    EXPECT_TRUE(tailgate::base::HasReadiness(result.Events.front().Readiness,
                                             tailgate::base::EventReadiness::Readable));
}
