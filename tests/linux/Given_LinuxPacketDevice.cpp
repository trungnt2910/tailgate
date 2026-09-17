#include <cstddef>
#include <cstdint>
#include <system_error>
#include <vector>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <tailgate/di/Bindings.h>
#include <tailgate/wgengine/Engine.h>
#include <tailgate/wgengine/tstun/Device.h>

#include "DI.h"
#include "DataplaneEvents.h"
#include "PacketDescriptorProvider.h"
#include "UniqueFd.h"

namespace
{

constexpr std::size_t MaximumEvents = 4;
constexpr std::size_t MaximumPackets = 4;
constexpr std::size_t MaximumPacketSize = 4096;

tailgate::wgengine::tstun::DeviceOptions DeviceOptions()
{
    return tailgate::wgengine::tstun::DeviceOptions{
        .Name = "tailgate-test",
        .ReadinessToken = tailgate::linux_frontend::DataplaneEvent(
                              tailgate::linux_frontend::DataplaneEvent::Kind::Tun)
                              .Token(),
    };
}

} // namespace

TEST(Given_LinuxPacketDevice, When_AdoptedDescriptorIsReadable_Then_EngineReturnsPacket)
{
    int descriptors[2]{};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, descriptors), 0);
    tailgate::linux_frontend::UniqueFd deviceDescriptor(descriptors[0]);
    tailgate::linux_frontend::UniqueFd peerDescriptor(descriptors[1]);
    tailgate::di::Injector injector;
    tailgate::linux_frontend::InstallBindings(injector);
    injector.create<tailgate::linux_frontend::PacketDescriptorProvider&>().Borrow(
        deviceDescriptor.Fd);
    tailgate::wgengine::Engine& engine = injector.create<tailgate::wgengine::Engine&>();
    ASSERT_TRUE(engine.OpenPacketDevice(DeviceOptions()));
    const std::vector<std::uint8_t> packet{1, 2, 3, 4};
    ASSERT_EQ(write(peerDescriptor.Fd, packet.data(), packet.size()),
              static_cast<ssize_t>(packet.size()));

    const tailgate::wgengine::EngineWaitResult result =
        engine.Wait(MaximumEvents, MaximumPackets, MaximumPacketSize);

    ASSERT_EQ(result.Packets.size(), 1U);
    EXPECT_EQ(result.Packets.front(), packet);
    EXPECT_TRUE(result.PlatformEvents.empty());
}

TEST(Given_LinuxPacketDevice, When_EngineWritesPacket_Then_AdoptedDescriptorReceivesPacket)
{
    int descriptors[2]{};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, descriptors), 0);
    tailgate::linux_frontend::UniqueFd deviceDescriptor(descriptors[0]);
    tailgate::linux_frontend::UniqueFd peerDescriptor(descriptors[1]);
    tailgate::di::Injector injector;
    tailgate::linux_frontend::InstallBindings(injector);
    injector.create<tailgate::linux_frontend::PacketDescriptorProvider&>().Borrow(
        deviceDescriptor.Fd);
    tailgate::wgengine::Engine& engine = injector.create<tailgate::wgengine::Engine&>();
    ASSERT_TRUE(engine.OpenPacketDevice(DeviceOptions()));
    const std::vector<std::uint8_t> packet{5, 6, 7, 8};

    const tailgate::wgengine::PacketWriteResult writeResult = engine.WritePacket(packet);
    std::vector<std::uint8_t> received(MaximumPacketSize);
    const ssize_t receivedSize = recv(peerDescriptor.Fd, received.data(), received.size(), 0);
    ASSERT_GT(receivedSize, 0);
    received.resize(static_cast<std::size_t>(receivedSize));

    EXPECT_EQ(writeResult, tailgate::wgengine::PacketWriteResult::Written);
    EXPECT_EQ(received, packet);
}

TEST(Given_LinuxPacketDevice, When_BorrowingSocket_Then_BlockingModeIsPreserved)
{
    int descriptors[2]{};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, descriptors), 0);
    tailgate::linux_frontend::UniqueFd deviceDescriptor(descriptors[0]);
    tailgate::linux_frontend::UniqueFd peerDescriptor(descriptors[1]);
    tailgate::di::Injector injector;
    tailgate::linux_frontend::InstallBindings(injector);
    injector.create<tailgate::linux_frontend::PacketDescriptorProvider&>().Borrow(
        deviceDescriptor.Fd);
    auto& device = injector.create<tailgate::wgengine::tstun::Device&>();
    const int originalFlags = fcntl(deviceDescriptor.Fd, F_GETFL);
    ASSERT_GE(originalFlags, 0);
    ASSERT_EQ(originalFlags & O_NONBLOCK, 0);

    const bool opened = device.Open(DeviceOptions());
    const int currentFlags = fcntl(deviceDescriptor.Fd, F_GETFL);
    const auto empty = device.TryRead(MaximumPacketSize);

    EXPECT_TRUE(opened);
    EXPECT_EQ(currentFlags, originalFlags);
    EXPECT_EQ(empty.Result, tailgate::wgengine::tstun::DeviceIoResult::WouldBlock);
}

TEST(Given_LinuxPacketDevice, When_PacketExceedsReadBudget_Then_TruncationIsRejected)
{
    int descriptors[2]{};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, descriptors), 0);
    tailgate::linux_frontend::UniqueFd deviceDescriptor(descriptors[0]);
    tailgate::linux_frontend::UniqueFd peerDescriptor(descriptors[1]);
    tailgate::di::Injector injector;
    tailgate::linux_frontend::InstallBindings(injector);
    injector.create<tailgate::linux_frontend::PacketDescriptorProvider&>().Borrow(
        deviceDescriptor.Fd);
    auto& device = injector.create<tailgate::wgengine::tstun::Device&>();
    ASSERT_TRUE(device.Open(DeviceOptions()));
    ASSERT_EQ(device.TryRead(MaximumPacketSize).Result,
              tailgate::wgengine::tstun::DeviceIoResult::WouldBlock);
    const std::vector<std::uint8_t> packet{1, 2, 3, 4};
    ASSERT_EQ(send(peerDescriptor.Fd, packet.data(), packet.size(), MSG_NOSIGNAL),
              static_cast<ssize_t>(packet.size()));
    std::error_code error;

    try
    {
        (void)device.TryRead(packet.size() - 1);
    }
    catch (const std::system_error& exception)
    {
        error = exception.code();
    }

    EXPECT_EQ(error, std::errc::message_size);
}

TEST(Given_LinuxPacketDevice, When_ReceiveStorageIsReused_Then_ReturnedPacketsOwnOnlyTheirData)
{
    int descriptors[2]{};
    ASSERT_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, descriptors), 0);
    tailgate::linux_frontend::UniqueFd deviceDescriptor(descriptors[0]);
    tailgate::linux_frontend::UniqueFd peerDescriptor(descriptors[1]);
    tailgate::di::Injector injector;
    tailgate::linux_frontend::InstallBindings(injector);
    injector.create<tailgate::linux_frontend::PacketDescriptorProvider&>().Borrow(
        deviceDescriptor.Fd);
    auto& device = injector.create<tailgate::wgengine::tstun::Device&>();
    ASSERT_TRUE(device.Open(DeviceOptions()));
    const std::vector<std::uint8_t> first{1, 2, 3, 4};
    const std::vector<std::uint8_t> second{5, 6};
    ASSERT_EQ(send(peerDescriptor.Fd, first.data(), first.size(), MSG_NOSIGNAL),
              static_cast<ssize_t>(first.size()));
    ASSERT_EQ(send(peerDescriptor.Fd, second.data(), second.size(), MSG_NOSIGNAL),
              static_cast<ssize_t>(second.size()));

    const auto firstRead = device.TryRead(MaximumPacketSize);
    const auto secondRead = device.TryRead(second.size());

    EXPECT_EQ(firstRead.Result, tailgate::wgengine::tstun::DeviceIoResult::Complete);
    EXPECT_EQ(secondRead.Result, tailgate::wgengine::tstun::DeviceIoResult::Complete);
    EXPECT_EQ(firstRead.Packet, first);
    EXPECT_EQ(secondRead.Packet, second);
}
