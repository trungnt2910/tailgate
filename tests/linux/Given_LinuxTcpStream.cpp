#include <cerrno>
#include <chrono>
#include <cstring>
#include <stop_token>
#include <string>
#include <system_error>
#include <vector>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <gtest/gtest.h>

#include <tailgate/types/nettype/TcpSocket.h>

#include "DI.h"
#include "UniqueFd.h"
#include "impl/TcpResolver.h"
#include "impl/TcpSocketBinder.h"

namespace
{

namespace linux_impl = tailgate::linux_frontend::impl;

class RecordingTcpResolver final : public linux_impl::TcpResolver
{
public:
    std::vector<linux_impl::TcpAddress> Resolve(const std::string& host,
                                                const std::string& service,
                                                std::chrono::seconds timeout,
                                                std::stop_token cancellation) override
    {
        ++Calls;
        Host = host;
        Service = service;
        Timeout = timeout;
        Cancellation = cancellation;
        if (Failure)
        {
            throw std::system_error(Failure);
        }
        return Addresses;
    }

    int Calls = 0;
    std::string Host;
    std::string Service;
    std::chrono::seconds Timeout{};
    std::stop_token Cancellation;
    std::error_code Failure;
    std::vector<linux_impl::TcpAddress> Addresses;
};

class RecordingTcpSocketBinder final : public linux_impl::TcpSocketBinder
{
public:
    void BindToInterface(int descriptor, const std::string& interfaceName) override
    {
        ++Calls;
        Descriptor = descriptor;
        Interface = interfaceName;
        sockaddr_storage peer{};
        socklen_t length = sizeof(peer);
        BeforeConnect = getpeername(descriptor, reinterpret_cast<sockaddr*>(&peer), &length) != 0 &&
                        errno == ENOTCONN;
        if (Failure)
        {
            throw std::system_error(Failure);
        }
    }

    int Calls = 0;
    int Descriptor = -1;
    std::string Interface;
    bool BeforeConnect = false;
    std::error_code Failure;
};

class Given_LinuxTcpStream : public testing::Test
{
protected:
    void SetUp() override
    {
        tailgate::linux_frontend::InstallBindings(Injector);
        Injector.InstallSingleton<RecordingTcpResolver, linux_impl::TcpResolver>();
        Injector.InstallSingleton<RecordingTcpSocketBinder, linux_impl::TcpSocketBinder>();
        Listener.Reset(socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0));
        ASSERT_GE(Listener.Fd, 0);
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ASSERT_EQ(bind(Listener.Fd, reinterpret_cast<const sockaddr*>(&address), sizeof(address)),
                  0);
        ASSERT_EQ(listen(Listener.Fd, 1), 0);
        socklen_t length = sizeof(address);
        ASSERT_EQ(getsockname(Listener.Fd, reinterpret_cast<sockaddr*>(&address), &length), 0);
        linux_impl::TcpAddress resolved;
        std::memcpy(&resolved.Address, &address, sizeof(address));
        resolved.Length = sizeof(address);
        resolved.Family = AF_INET;
        resolved.Protocol = IPPROTO_TCP;
        Resolver().Addresses.push_back(resolved);
        Options.ConnectAddress = "server.example.ts.net";
        Options.Service = "443";
        Options.IoTimeout = std::chrono::seconds(5);
        Options.ConnectTimeout = std::chrono::seconds(2);
    }

    RecordingTcpResolver& Resolver()
    {
        return Injector.create<RecordingTcpResolver&>();
    }

    RecordingTcpSocketBinder& Binder()
    {
        return Injector.create<RecordingTcpSocketBinder&>();
    }

    tailgate::types::nettype::TcpSocketFactory& Factory()
    {
        return Injector.create<tailgate::types::nettype::TcpSocketFactory&>();
    }

    tailgate::di::Injector Injector;
    tailgate::linux_frontend::UniqueFd Listener;
    tailgate::types::nettype::TcpSocketOptions Options;
};

TEST_F(Given_LinuxTcpStream, When_InterfaceIsSelected_Then_ResolvedTcpSocketIsBoundBeforeConnect)
{
    Options.NetworkInterface = "test-underlay";
    std::stop_source cancellation;
    Options.Cancellation = cancellation.get_token();
    sockaddr_in peer{};
    socklen_t length = sizeof(peer);
    const auto& expected =
        reinterpret_cast<const sockaddr_in&>(Resolver().Addresses.front().Address);

    const auto socket = Factory().OpenTcpSocket(Options);
    const int peerResult =
        getpeername(Binder().Descriptor, reinterpret_cast<sockaddr*>(&peer), &length);

    EXPECT_NE(socket, nullptr);
    EXPECT_EQ(Resolver().Calls, 1);
    EXPECT_EQ(Resolver().Host, Options.ConnectAddress);
    EXPECT_EQ(Resolver().Service, Options.Service);
    EXPECT_EQ(Resolver().Timeout, Options.ConnectTimeout);
    EXPECT_EQ(Resolver().Cancellation, Options.Cancellation);
    EXPECT_EQ(Binder().Calls, 1);
    EXPECT_EQ(Binder().Interface, Options.NetworkInterface);
    EXPECT_TRUE(Binder().BeforeConnect);
    EXPECT_EQ(peerResult, 0);
    EXPECT_EQ(peer.sin_family, AF_INET);
    EXPECT_EQ(peer.sin_addr.s_addr, expected.sin_addr.s_addr);
    EXPECT_EQ(peer.sin_port, expected.sin_port);
}

TEST_F(Given_LinuxTcpStream, When_NoInterfaceIsSelected_Then_ConnectionUsesDefaultRouting)
{
    Options.ConnectTimeout.reset();

    const auto socket = Factory().OpenTcpSocket(Options);

    EXPECT_NE(socket, nullptr);
    EXPECT_EQ(Resolver().Calls, 1);
    EXPECT_EQ(Resolver().Timeout, Options.IoTimeout);
    EXPECT_EQ(Binder().Calls, 0);
}

TEST_F(Given_LinuxTcpStream, When_ResolutionFails_Then_InterfaceBindingIsNotAttempted)
{
    Options.NetworkInterface = "test-underlay";
    Resolver().Failure = std::make_error_code(std::errc::host_unreachable);
    std::error_code result;

    try
    {
        (void)Factory().OpenTcpSocket(Options);
    }
    catch (const std::system_error& error)
    {
        result = error.code();
    }

    EXPECT_EQ(result, Resolver().Failure);
    EXPECT_EQ(Resolver().Calls, 1);
    EXPECT_EQ(Binder().Calls, 0);
}

TEST_F(Given_LinuxTcpStream,
       When_InterfaceBindingFails_Then_ConnectionDoesNotFallBackToDefaultRouting)
{
    Options.NetworkInterface = "test-underlay";
    Binder().Failure = std::make_error_code(std::errc::no_such_device);
    std::error_code result;

    try
    {
        (void)Factory().OpenTcpSocket(Options);
    }
    catch (const std::system_error& error)
    {
        result = error.code();
    }

    EXPECT_EQ(result, Binder().Failure);
    EXPECT_EQ(Resolver().Calls, 1);
    EXPECT_EQ(Binder().Calls, 1);
    EXPECT_TRUE(Binder().BeforeConnect);
}

TEST_F(Given_LinuxTcpStream, When_OpenIsAlreadyCancelled_Then_ResolverAndBinderAreNotCalled)
{
    std::stop_source cancellation;
    cancellation.request_stop();
    Options.Cancellation = cancellation.get_token();
    Options.NetworkInterface = "test-underlay";
    std::error_code result;

    try
    {
        (void)Factory().OpenTcpSocket(Options);
    }
    catch (const std::system_error& error)
    {
        result = error.code();
    }

    EXPECT_EQ(result, std::errc::operation_canceled);
    EXPECT_EQ(Resolver().Calls, 0);
    EXPECT_EQ(Binder().Calls, 0);
}

} // namespace
