#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/base/EventLoop.h>
#include <tailgate/crypto/Crypto.h>
#include <tailgate/di/Bindings.h>
#include <tailgate/net/Endpoint.h>
#include <tailgate/types/nettype/UdpSocket.h>
#include <tailgate/wgengine/Engine.h>
#include <tailgate/wgengine/magicsock/Connection.h>
#include <tailgate/wgengine/tstun/Device.h>

#include "fakes/di/FakeNetworkBindings.h"

namespace
{

namespace magicsock = tailgate::wgengine::magicsock;
namespace nettype = tailgate::types::nettype;
using tailgate::tests::fakes::FakeDevice;
using tailgate::tests::fakes::FakeEventLoop;
using tailgate::tests::fakes::FakeTimeProvider;
using tailgate::tests::fakes::FakeUdpSocketFactory;

constexpr tailgate::base::EventToken SharedToken{.Value = 100};
constexpr tailgate::base::EventToken PlatformToken{.Value = 200};
constexpr tailgate::base::EventToken DeviceToken{.Value = 300};
constexpr std::size_t MaximumEvents = 8;
constexpr std::size_t MaximumDatagrams = 4;
constexpr std::size_t MaximumDatagramSize = 4096;

tailgate::crypto::Bytes32 Peer()
{
    tailgate::crypto::Bytes32 peer{};
    peer.front() = 1;
    return peer;
}

tailgate::net::Endpoint Endpoint()
{
    return tailgate::net::Endpoint(tailgate::net::Ipv4Address::FromOctets(192, 0, 2, 1), 41641);
}

nettype::UdpSocketOptions Options(tailgate::base::EventToken token)
{
    return nettype::UdpSocketOptions{
        .BindEndpoint = {},
        .NetworkInterface = std::nullopt,
        .ReadinessToken = token,
    };
}

TEST(Given_WgengineEngine, When_CoreSocketIsReadable_Then_CoreDrainsTheDatagram)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto* eventLoop = &dynamic_cast<FakeEventLoop&>(injector.create<tailgate::base::EventLoop&>());
    auto* socketFactory = &dynamic_cast<FakeUdpSocketFactory&>(
        injector.create<tailgate::types::nettype::UdpSocketFactory&>());
    magicsock::Connection& connection = injector.create<magicsock::Connection&>();
    tailgate::wgengine::Engine& engine = injector.create<tailgate::wgengine::Engine&>();
    ASSERT_TRUE(connection.Open(Options(SharedToken)));
    ASSERT_TRUE(connection.AddPeer(Peer()));
    ASSERT_EQ(socketFactory->States.size(), 1U);
    const nettype::UdpDatagram datagram{.Source = Endpoint(), .Payload = {1, 2, 3}};
    socketFactory->States.front()->Incoming.push_back(nettype::UdpReceiveResult{
        .Result = nettype::SocketIoResult::Complete,
        .Datagram = datagram,
    });
    eventLoop->Next.Events.push_back(tailgate::base::Event{
        .Token = SharedToken,
        .Readiness = tailgate::base::EventReadiness::Readable,
    });

    const tailgate::wgengine::EngineWaitResult result =
        engine.Wait(MaximumEvents, MaximumDatagrams, MaximumDatagramSize);

    ASSERT_EQ(result.Datagrams.size(), 1U);
    EXPECT_EQ(eventLoop->WaitCalls, 1U);
    EXPECT_EQ(eventLoop->TimedWaitCalls, 0U);
    EXPECT_EQ(result.Datagrams.front().Source, datagram.Source);
    EXPECT_EQ(result.Datagrams.front().Payload, datagram.Payload);
    EXPECT_TRUE(result.PlatformEvents.empty());
}

TEST(Given_WgengineEngine, When_PlatformPrimitiveIsReadable_Then_EventIsPreserved)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto* eventLoop = &dynamic_cast<FakeEventLoop&>(injector.create<tailgate::base::EventLoop&>());
    tailgate::wgengine::Engine& engine = injector.create<tailgate::wgengine::Engine&>();
    eventLoop->Next.Events.push_back(tailgate::base::Event{
        .Token = PlatformToken,
        .Readiness = tailgate::base::EventReadiness::Readable,
    });

    const tailgate::wgengine::EngineWaitResult result =
        engine.Wait(MaximumEvents, MaximumDatagrams, MaximumDatagramSize);

    ASSERT_EQ(result.PlatformEvents.size(), 1U);
    EXPECT_EQ(result.PlatformEvents.front().Token, PlatformToken);
    EXPECT_TRUE(result.Datagrams.empty());
    EXPECT_TRUE(result.Failures.empty());
}

TEST(Given_WgengineEngine, When_PacketDeviceIsReadable_Then_CoreDrainsThePacket)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto* eventLoop = &dynamic_cast<FakeEventLoop&>(injector.create<tailgate::base::EventLoop&>());
    auto* device =
        &dynamic_cast<FakeDevice&>(injector.create<tailgate::wgengine::tstun::Device&>());
    tailgate::wgengine::Engine& engine = injector.create<tailgate::wgengine::Engine&>();
    ASSERT_TRUE(engine.OpenPacketDevice(tailgate::wgengine::tstun::DeviceOptions{
        .Name = "tailgate-test",
        .ReadinessToken = DeviceToken,
    }));
    const std::vector<std::uint8_t> packet{4, 5, 6};
    device->Incoming.push_back(tailgate::wgengine::tstun::DeviceReadResult{
        .Result = tailgate::wgengine::tstun::DeviceIoResult::Complete,
        .Packet = packet,
    });
    eventLoop->Next.Events.push_back(tailgate::base::Event{
        .Token = DeviceToken,
        .Readiness = tailgate::base::EventReadiness::Readable,
    });

    const tailgate::wgengine::EngineWaitResult result =
        engine.Wait(MaximumEvents, MaximumDatagrams, MaximumDatagramSize);

    ASSERT_EQ(result.Packets.size(), 1U);
    EXPECT_EQ(result.Packets.front(), packet);
    EXPECT_TRUE(result.PlatformEvents.empty());
}

TEST(Given_WgengineEngine, When_QueuedPacketDeviceBecomesWritable_Then_CoreFlushesThePacket)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto* eventLoop = &dynamic_cast<FakeEventLoop&>(injector.create<tailgate::base::EventLoop&>());
    auto* device =
        &dynamic_cast<FakeDevice&>(injector.create<tailgate::wgengine::tstun::Device&>());
    tailgate::wgengine::Engine& engine = injector.create<tailgate::wgengine::Engine&>();
    ASSERT_TRUE(engine.OpenPacketDevice(tailgate::wgengine::tstun::DeviceOptions{
        .Name = "tailgate-test",
        .ReadinessToken = DeviceToken,
    }));
    const std::vector<std::uint8_t> packet{7, 8, 9};
    device->WriteResult = tailgate::wgengine::tstun::DeviceIoResult::WouldBlock;
    ASSERT_EQ(engine.WritePacket(packet), tailgate::wgengine::PacketWriteResult::Queued);
    ASSERT_TRUE(device->WriteInterest);
    device->WriteResult = tailgate::wgengine::tstun::DeviceIoResult::Complete;
    eventLoop->Next.Events.push_back(tailgate::base::Event{
        .Token = DeviceToken,
        .Readiness = tailgate::base::EventReadiness::Writable,
    });

    const tailgate::wgengine::EngineWaitResult result =
        engine.Wait(MaximumEvents, MaximumDatagrams, MaximumDatagramSize);

    ASSERT_EQ(device->Written.size(), 1U);
    EXPECT_EQ(device->Written.front(), packet);
    EXPECT_FALSE(device->WriteInterest);
    EXPECT_TRUE(result.PlatformEvents.empty());
}

TEST(Given_WgengineEngine, When_TimeTokenIsSignaled_Then_DeadlineIsReturned)
{
    FakeTimeProvider timeProvider;
    std::unique_ptr<tailgate::base::WaitToken> deadline = timeProvider.At(timeProvider.Now());
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto* eventLoop = &dynamic_cast<FakeEventLoop&>(injector.create<tailgate::base::EventLoop&>());
    tailgate::wgengine::Engine& engine = injector.create<tailgate::wgengine::Engine&>();

    const tailgate::wgengine::EngineWaitResult result =
        engine.Wait(*deadline, MaximumEvents, MaximumDatagrams, MaximumDatagramSize);

    EXPECT_EQ(eventLoop->TimedWaitCalls, 1U);
    EXPECT_EQ(result.Status, tailgate::base::EventWaitStatus::DeadlineReached);
    EXPECT_TRUE(result.Datagrams.empty());
    EXPECT_TRUE(result.Failures.empty());
    EXPECT_TRUE(result.PlatformEvents.empty());
}

TEST(Given_WgengineEngine, When_QueuedSocketBecomesWritable_Then_CoreFlushesIt)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto* eventLoop = &dynamic_cast<FakeEventLoop&>(injector.create<tailgate::base::EventLoop&>());
    auto* socketFactory = &dynamic_cast<FakeUdpSocketFactory&>(
        injector.create<tailgate::types::nettype::UdpSocketFactory&>());
    magicsock::Connection& connection = injector.create<magicsock::Connection&>();
    tailgate::wgengine::Engine& engine = injector.create<tailgate::wgengine::Engine&>();
    ASSERT_TRUE(connection.Open(Options(SharedToken)));
    ASSERT_TRUE(connection.AddPeer(Peer()));
    ASSERT_EQ(socketFactory->States.size(), 1U);
    socketFactory->States.front()->SendResult = nettype::SocketIoResult::WouldBlock;
    ASSERT_EQ(connection.SendDirect(Peer(), Endpoint(), {4, 5, 6}),
              magicsock::Connection::DirectSendResult::Queued);
    socketFactory->States.front()->SendResult = nettype::SocketIoResult::Complete;
    eventLoop->Next.Events.push_back(tailgate::base::Event{
        .Token = SharedToken,
        .Readiness = tailgate::base::EventReadiness::Writable,
    });

    const tailgate::wgengine::EngineWaitResult result =
        engine.Wait(MaximumEvents, MaximumDatagrams, MaximumDatagramSize);

    EXPECT_TRUE(result.Failures.empty());
    EXPECT_EQ(connection.QueuedPackets(Peer()), 0U);
    EXPECT_EQ(socketFactory->States.front()->Sent.size(), 1U);
    EXPECT_FALSE(socketFactory->States.front()->WriteInterest);
}

TEST(Given_WgengineEngine, When_CoreSocketCloses_Then_TypedFailureIsReturned)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto* eventLoop = &dynamic_cast<FakeEventLoop&>(injector.create<tailgate::base::EventLoop&>());
    magicsock::Connection& connection = injector.create<magicsock::Connection&>();
    tailgate::wgengine::Engine& engine = injector.create<tailgate::wgengine::Engine&>();
    ASSERT_TRUE(connection.Open(Options(SharedToken)));
    eventLoop->Next.Events.push_back(tailgate::base::Event{
        .Token = SharedToken,
        .Readiness = tailgate::base::EventReadiness::Closed,
    });

    const tailgate::wgengine::EngineWaitResult result =
        engine.Wait(MaximumEvents, MaximumDatagrams, MaximumDatagramSize);

    ASSERT_EQ(result.Failures.size(), 1U);
    EXPECT_EQ(result.Failures.front().Status, magicsock::Connection::EventStatus::Closed);
}

} // namespace
