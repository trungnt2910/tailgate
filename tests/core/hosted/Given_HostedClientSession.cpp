#include <cstddef>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/base/EventLoop.h>
#include <tailgate/di/Bindings.h>
#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/ClientSession.h>
#include <tailgate/hosted/Protocol.h>

#include "fakes/di/FakeNetworkBindings.h"
#include "fakes/wgengine/tstun/FakeDevice.h"

namespace
{

constexpr tailgate::base::EventToken ReadinessToken{.Value = 1};
constexpr std::size_t MaximumPackets = 1;
constexpr std::size_t MaximumPacketSize = 4096;

TEST(Given_HostedClientSession, When_DevicePacketIsAvailable_Then_CoreConsumesIt)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto& subject = injector.create<tailgate::hosted::ClientSession&>();
    auto& device = injector.create<tailgate::tests::fakes::FakeDevice&>();
    ASSERT_TRUE(subject.OpenPacketDevice(tailgate::wgengine::tstun::DeviceOptions{
        .Name = {},
        .ReadinessToken = ReadinessToken,
    }));
    device.Incoming.push_back(tailgate::wgengine::tstun::DeviceReadResult{
        .Result = tailgate::wgengine::tstun::DeviceIoResult::Complete,
        .Packet = {1, 2, 3, 4},
    });

    const tailgate::hosted::ClientSessionProcessResult result =
        subject.ProcessPacketDevice(MaximumPackets, MaximumPacketSize);

    EXPECT_EQ(result.DeviceStatus, tailgate::hosted::PacketDeviceStatus::Ready);
    EXPECT_TRUE(result.RemoteOutput.empty());
    EXPECT_TRUE(device.Incoming.empty());
}

TEST(Given_HostedClientSession, When_HeartbeatArrives_Then_CoreReturnsResponse)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto& subject = injector.create<tailgate::hosted::ClientSession&>();
    const tailgate::hosted::Frame heartbeat(tailgate::hosted::MessageType::Heartbeat, {});

    const tailgate::hosted::ClientSessionProcessResult result = subject.ProcessFrame(heartbeat);
    tailgate::hosted::Decoder decoder;
    decoder.Feed(result.RemoteOutput);
    const auto response = decoder.Next();

    ASSERT_TRUE(response.has_value());
    EXPECT_EQ(response->Type(), tailgate::hosted::MessageType::Heartbeat);
    EXPECT_TRUE(response->Payload().empty());
}

TEST(Given_HostedClientSession, When_DataPathReadyArrives_Then_CoreReportsReadiness)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto& subject = injector.create<tailgate::hosted::ClientSession&>();
    const tailgate::hosted::Frame ready(tailgate::hosted::MessageType::DataPathReady, {});

    const tailgate::hosted::ClientSessionProcessResult result = subject.ProcessFrame(ready);

    EXPECT_TRUE(result.DataPathReady);
    EXPECT_TRUE(result.RemoteOutput.empty());
}

TEST(Given_HostedClientSession, When_DeviceIsClosed_Then_CoreReportsClosed)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto& subject = injector.create<tailgate::hosted::ClientSession&>();

    const tailgate::hosted::ClientSessionProcessResult result =
        subject.ProcessPacketDevice(MaximumPackets, MaximumPacketSize);

    EXPECT_EQ(result.DeviceStatus, tailgate::hosted::PacketDeviceStatus::Closed);
}

TEST(Given_HostedClientSession, When_PacketIsWrittenToDevice_Then_CoreForwardsIt)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto& subject = injector.create<tailgate::hosted::ClientSession&>();
    auto& device = injector.create<tailgate::tests::fakes::FakeDevice&>();
    ASSERT_TRUE(subject.OpenPacketDevice(tailgate::wgengine::tstun::DeviceOptions{
        .Name = {},
        .ReadinessToken = ReadinessToken,
    }));
    const std::vector<std::uint8_t> packet{1, 2, 3, 4};

    const tailgate::hosted::PacketDeviceStatus result = subject.WritePacketDevice(packet);

    EXPECT_EQ(result, tailgate::hosted::PacketDeviceStatus::Ready);
    EXPECT_EQ(device.Written, std::vector<std::vector<std::uint8_t>>{packet});
}

} // namespace
