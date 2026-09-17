#include <cstddef>
#include <cstdint>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/base/EventLoop.h>
#include <tailgate/di/Bindings.h>
#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/ClientSession.h>
#include <tailgate/hosted/Protocol.h>
#include <tailgate/hosted/Pump.h>
#include <tailgate/net/packet/Ipv4.h>

#include "fakes/di/FakeNetworkBindings.h"
#include "fakes/drive/FakeTcpStack.h"
#include "fakes/wgengine/tstun/FakeDevice.h"

namespace tailgate::tests
{
namespace
{

class Given_HostedClientSession : public testing::Test
{
protected:
    Given_HostedClientSession()
    {
        fakes::InstallFakeNetworkBindings(m_injector);
        m_injector.InstallSingleton<fakes::FakeTcpStack, wgengine::netstack::Stack>();
        m_stack = m_injector.create<std::shared_ptr<fakes::FakeTcpStack>>();
        m_client = &m_injector.create<hosted::Client&>();
        m_session = &m_injector.create<hosted::ClientSession&>();
        m_device = &m_injector.create<fakes::FakeDevice&>();
        m_config.NodePrivateKey = crypto::GeneratePrivateKey();
        m_config.NodePublicKey = crypto::X25519PublicFromPrivate(m_config.NodePrivateKey);
        m_config.Network.SelfKey("nodekey:" + crypto::BytesToHex(m_config.NodePublicKey.data(),
                                                                 m_config.NodePublicKey.size()));
        m_config.Network.SelfNodeId(1);
        m_config.Network.SelfAddress("192.0.2.1");
        m_config.Network.Domain("example.ts.net");
        m_config.Network.Capabilities({"drive:access"});
        (void)m_client->Start(m_config);
    }

    void Open()
    {
        ASSERT_TRUE(m_session->OpenPacketDevice({.Name = {}, .ReadinessToken = {.Value = 1}}));
    }

    di::Injector m_injector;
    std::shared_ptr<fakes::FakeTcpStack> m_stack;
    hosted::Client* m_client = nullptr;
    hosted::ClientSession* m_session = nullptr;
    fakes::FakeDevice* m_device = nullptr;
    hosted::ClientConfig m_config;
};

constexpr tailgate::base::EventToken ReadinessToken{.Value = 1};
constexpr std::size_t MaximumPackets = 1;
constexpr std::size_t MaximumPacketSize = 4096;

TEST_F(Given_HostedClientSession, When_DevicePacketIsAvailable_Then_CoreConsumesIt)
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

TEST_F(Given_HostedClientSession, When_HeartbeatArrives_Then_CoreReturnsResponse)
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

TEST_F(Given_HostedClientSession, When_DataPathReadyArrives_Then_CoreReportsReadiness)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto& subject = injector.create<tailgate::hosted::ClientSession&>();
    const tailgate::hosted::Frame ready(tailgate::hosted::MessageType::DataPathReady, {});

    const tailgate::hosted::ClientSessionProcessResult result = subject.ProcessFrame(ready);

    EXPECT_TRUE(result.DataPathReady);
    EXPECT_TRUE(result.RemoteOutput.empty());
}

TEST_F(Given_HostedClientSession, When_PumpArrives_Then_CoreReportsItWithoutHeartbeatOrProbes)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto& subject = injector.create<tailgate::hosted::ClientSession&>();
    const auto frame = tailgate::hosted::EncodePumpReply(42);

    const auto result = subject.ProcessFrame(frame);

    EXPECT_EQ(result.PumpReply, 42U);
    EXPECT_TRUE(result.RemoteOutput.empty());
}

TEST_F(Given_HostedClientSession, When_DeviceIsClosed_Then_CoreReportsClosed)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto& subject = injector.create<tailgate::hosted::ClientSession&>();

    const tailgate::hosted::ClientSessionProcessResult result =
        subject.ProcessPacketDevice(MaximumPackets, MaximumPacketSize);

    EXPECT_EQ(result.DeviceStatus, tailgate::hosted::PacketDeviceStatus::Closed);
}

TEST_F(Given_HostedClientSession, When_PacketIsWrittenToDevice_Then_CoreForwardsIt)
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

TEST_F(Given_HostedClientSession,
       When_Quad100TcpArrivesFromDevice_Then_CoreInterceptsBeforeEncapsulation)
{
    ASSERT_NO_FATAL_FAILURE(Open());
    const auto packet =
        net::packet::Ipv4Packet::Build(net::Ipv4Address::FromOctets(192, 0, 2, 1).HostOrder(),
                                       net::Ipv4Address::FromOctets(100, 100, 100, 100).HostOrder(),
                                       6,
                                       std::vector<std::uint8_t>(20));
    m_device->Incoming.push_back(
        {.Result = wgengine::tstun::DeviceIoResult::Complete, .Packet = packet});

    const auto result = m_session->ProcessPacketDevice(1, 4096);
    ASSERT_EQ(m_stack->InputPackets.size(), 1U);

    EXPECT_EQ(result.DeviceStatus, hosted::PacketDeviceStatus::Ready);
    EXPECT_TRUE(result.RemoteOutput.empty());
    EXPECT_EQ(m_stack->InputPackets.size(), 1U);
    EXPECT_EQ(m_stack->InputPackets.front().Path, wgengine::netstack::PacketPath::Host);
    EXPECT_EQ(m_stack->InputPackets.front().Bytes, packet);
}

TEST_F(Given_HostedClientSession, When_LocalTcpProducesReply_Then_PollWritesItToPacketDevice)
{
    ASSERT_NO_FATAL_FAILURE(Open());
    const std::vector<std::uint8_t> packet{1, 2, 3};
    m_stack->Output.push_back({.Path = wgengine::netstack::PacketPath::Host, .Bytes = packet});

    const auto result = m_session->PollLocalServices();

    EXPECT_EQ(result.DeviceStatus, hosted::PacketDeviceStatus::Ready);
    EXPECT_TRUE(result.RemoteOutput.empty());
    EXPECT_EQ(m_device->Written, (std::vector<std::vector<std::uint8_t>>{packet}));
}

TEST_F(Given_HostedClientSession,
       When_ReassembledNonTcpHostPacketIsReturned_Then_ItIsNotInjectedAsReply)
{
    ASSERT_NO_FATAL_FAILURE(Open());
    const auto packet =
        net::packet::Ipv4Packet::Build(net::Ipv4Address::FromOctets(192, 0, 2, 1).HostOrder(),
                                       net::Ipv4Address::FromOctets(100, 100, 100, 100).HostOrder(),
                                       17,
                                       std::vector<std::uint8_t>(20));
    m_stack->Output.push_back(
        {.Path = wgengine::netstack::PacketPath::HostNetwork, .Bytes = packet});

    const auto result = m_session->PollLocalServices();

    EXPECT_EQ(result.DeviceStatus, hosted::PacketDeviceStatus::Ready);
    EXPECT_TRUE(m_device->Written.empty());
}

TEST_F(Given_HostedClientSession, When_TcpHasDeadline_Then_HostWaitCanUseIt)
{
    ASSERT_NO_FATAL_FAILURE(Open());
    (void)m_session->PollLocalServices();
    const auto deadline = base::TimeProvider::TimePoint{} + std::chrono::milliseconds(25);
    m_stack->Deadline = deadline;

    const auto actual = m_session->NextDeadline();

    EXPECT_EQ(actual, deadline);
}

TEST_F(Given_HostedClientSession, When_DeviceCloses_Then_LocalTcpAndDeadlinesAreRetired)
{
    ASSERT_NO_FATAL_FAILURE(Open());

    m_session->ClosePacketDevice();

    EXPECT_EQ(m_stack->Stops, 1U);
    EXPECT_FALSE(m_session->NextDeadline().has_value());
    EXPECT_EQ(m_session->PollLocalServices().DeviceStatus, hosted::PacketDeviceStatus::Closed);
}

TEST_F(Given_HostedClientSession, When_NetworkMapChanges_Then_ActiveServiceCatalogRefreshes)
{
    ASSERT_NO_FATAL_FAILURE(Open());
    auto next = m_config.Network;
    next.SelfAddress("192.0.2.3");
    const hosted::Frame frame(hosted::MessageType::NetworkMap,
                              hosted::ProtocolCodec::EncodeNetworkConfig(next));

    const auto result = m_session->ProcessFrame(frame);

    EXPECT_TRUE(result.NetworkMapChanged);
    EXPECT_EQ(m_stack->Starts, 2U);
    EXPECT_EQ(m_stack->Stops, 1U);
    EXPECT_EQ(m_stack->Configuration.Node.Ipv4, net::IpAddress::Parse("192.0.2.3"));
}

TEST_F(Given_HostedClientSession, When_ControlStartsAfterDevice_Then_RefreshEnablesLocalServices)
{
    m_client->Stop();
    ASSERT_NO_FATAL_FAILURE(Open());
    ASSERT_EQ(m_stack->Starts, 0U);
    (void)m_client->Start(m_config);

    m_session->RefreshNetworkConfig();

    EXPECT_EQ(m_stack->Starts, 1U);
    EXPECT_EQ(m_stack->Listening.size(), 1U);
    EXPECT_EQ(m_stack->Configuration.Node.Ipv4, net::IpAddress::Parse("192.0.2.1"));
}

} // namespace
} // namespace tailgate::tests
