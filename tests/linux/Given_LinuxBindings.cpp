#include <memory>
#include <type_traits>

#include <gtest/gtest.h>

#include <tailgate/PlatformFrontend.h>
#include <tailgate/base/EventLoop.h>
#include <tailgate/base/TimeProvider.h>
#include <tailgate/derp/Connection.h>
#include <tailgate/hosted/Connection.h>
#include <tailgate/types/nettype/TcpSocket.h>
#include <tailgate/types/nettype/UdpSocket.h>
#include <tailgate/wgengine/Engine.h>
#include <tailgate/wgengine/magicsock/Connection.h>

#include "DI.h"
#include "PacketDescriptorProvider.h"
#include "impl/EventLoop.h"
#include "impl/TcpSocketFactory.h"
#include "impl/TimeProvider.h"
#include "impl/UdpSocketFactory.h"

TEST(Given_LinuxBindings, When_CreatingFrontend_Then_ProductionGraphIsComplete)
{
    std::unique_ptr<tailgate::platform::IPlatformFrontend> frontend =
        tailgate::platform::CreateFrontend();

    const bool created = frontend != nullptr;

    EXPECT_TRUE(created);
}

TEST(Given_LinuxBindings, When_CreatingNetworkSession_Then_EventAndSocketPrimitivesAreComplete)
{
    tailgate::di::Injector injector;
    tailgate::linux_frontend::InstallBindings(injector);

    tailgate::base::EventLoop& eventLoop = injector.create<tailgate::base::EventLoop&>();
    tailgate::base::TimeProvider& timeProvider = injector.create<tailgate::base::TimeProvider&>();
    tailgate::types::nettype::UdpSocketFactory& socketFactory =
        injector.create<tailgate::types::nettype::UdpSocketFactory&>();
    tailgate::types::nettype::TcpSocketFactory& tcpSocketFactory =
        injector.create<tailgate::types::nettype::TcpSocketFactory&>();
    tailgate::hosted::Connection& hostedConnection =
        injector.create<tailgate::hosted::Connection&>();
    tailgate::derp::ConnectionFactory& derpConnectionFactory =
        injector.create<tailgate::derp::ConnectionFactory&>();
    tailgate::wgengine::Engine& engine = injector.create<tailgate::wgengine::Engine&>();
    tailgate::wgengine::magicsock::Connection& connection =
        injector.create<tailgate::wgengine::magicsock::Connection&>();
    const bool eventLoopIsLinux =
        dynamic_cast<tailgate::linux_frontend::impl::EventLoop*>(&eventLoop) != nullptr;
    const bool timeProviderIsLinux =
        dynamic_cast<tailgate::linux_frontend::impl::TimeProvider*>(&timeProvider) != nullptr;
    const bool socketFactoryIsLinux =
        dynamic_cast<tailgate::linux_frontend::impl::UdpSocketFactory*>(&socketFactory) != nullptr;
    const bool tcpSocketFactoryIsLinux =
        dynamic_cast<tailgate::linux_frontend::impl::TcpSocketFactory*>(&tcpSocketFactory) !=
        nullptr;
    const bool coreRuntimeIsAbstract =
        std::is_abstract_v<tailgate::wgengine::Engine> &&
        std::is_abstract_v<tailgate::wgengine::magicsock::Connection>;
    (void)engine;
    (void)connection;
    (void)hostedConnection;
    (void)derpConnectionFactory;

    EXPECT_TRUE(eventLoopIsLinux);
    EXPECT_TRUE(timeProviderIsLinux);
    EXPECT_TRUE(socketFactoryIsLinux);
    EXPECT_TRUE(tcpSocketFactoryIsLinux);
    EXPECT_TRUE(coreRuntimeIsAbstract);
}

TEST(Given_LinuxBindings, When_ResolvingPacketDescriptorProvider_Then_ProductionGraphIsScoped)
{
    tailgate::di::Injector injector;
    tailgate::linux_frontend::InstallBindings(injector);

    const auto* first = &injector.create<tailgate::linux_frontend::PacketDescriptorProvider&>();
    const auto* second = &injector.create<tailgate::linux_frontend::PacketDescriptorProvider&>();

    EXPECT_EQ(first, second);
}
