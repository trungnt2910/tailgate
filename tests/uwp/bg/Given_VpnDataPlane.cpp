#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include <tailgate/hosted/Pump.h>
#include <tailgate/net/http/Client.h>
#include <tailgate/wgengine/netstack/Stack.h>

#include "manager/impl/DataPlaneManagerImpl.h"
#include "service/NetworkService.h"
#include "service/PingService.h"

#include "fakes/bg/manager/FakeSessionManager.h"
#include "fakes/di/FakeNetworkBindings.h"

namespace tailgate::uwp::tests
{
namespace netstack = tailgate::wgengine::netstack;

class Given_VpnDataPlane : public testing::Test
{
protected:
    void SetUp() override
    {
        tailgate::tests::fakes::InstallFakeNetworkBindings(m_injector);
        m_injector.InstallSingleton<bg::PacketDevice, tailgate::wgengine::tstun::Device>();
        m_injector.InstallSingleton<FakeSessionManager, bg::manager::SessionManager>();
        m_injector.install(
            boost::di::bind<bg::manager::DataPlaneManager>.to<bg::manager::DataPlaneManagerImpl>(),
            boost::di::bind<bg::service::PingService>(),
            boost::di::bind<bg::service::NetworkService>());
        tailgate::hosted::ClientConfig config;
        config.NodePrivateKey = crypto::GeneratePrivateKey();
        config.NodePublicKey = crypto::X25519PublicFromPrivate(config.NodePrivateKey);
        config.Network.SelfKey("nodekey:" + crypto::BytesToHex(config.NodePublicKey.data(),
                                                               config.NodePublicKey.size()));
        config.Network.SelfAddress("192.0.2.1");
        config.Network.Domain("example.ts.net");
        config.Network.Capabilities({"drive:access"});
        m_client = &m_injector.create<tailgate::hosted::Client&>();
        (void)m_client->Start(config);
        (void)m_injector.create<bg::service::NetworkService&>();
        m_subject = &m_injector.create<bg::manager::DataPlaneManager&>();
        m_subject->Start(1);
        m_stack = &m_injector.create<netstack::Stack&>();
        m_host = m_stack->Connect(netstack::TcpEndpoint{
            .Address = net::IpAddress::Parse("100.100.100.100"), .Port = 8080});
    }

    void SendHostPackets()
    {
        const auto packets = m_stack->TakeOutput(64);
        ASSERT_FALSE(packets.empty());
        const std::string relay = "relay.example.com";
        for (const auto& packet : packets)
        {
            ASSERT_EQ(packet.Path, netstack::PacketPath::Peer);
            bg::service::EncapsulationContext context{.Original = packet.Bytes,
                                                      .Client = *m_client,
                                                      .RelayName = relay,
                                                      .RemoteOutput = m_remote};
            m_subject->Encapsulate(context);
        }
    }

    std::optional<tailgate::hosted::PumpSchedule> LastSchedule()
    {
        tailgate::hosted::Decoder decoder;
        decoder.Feed(m_remote);
        std::optional<tailgate::hosted::PumpSchedule> result;
        while (const auto frame = decoder.Next())
        {
            if (frame->Type() == tailgate::hosted::MessageType::PumpSchedule)
            {
                result = tailgate::hosted::TryDecodePumpSchedule(frame->Payload());
            }
        }
        return result;
    }

    void ReceivePump(std::uint64_t requestId)
    {
        m_remote.clear();
        const auto frame = tailgate::hosted::EncodePumpReply(requestId);
        std::vector<std::vector<std::uint8_t>> local;
        bg::service::DecapsulationContext context{
            .Message = frame, .Client = *m_client, .LocalOutput = local, .RemoteOutput = m_remote};
        m_subject->Decapsulate(context);
        m_subject->FlushLocal(local, m_remote);
        for (const auto& packet : local)
        {
            // The second interface acts as the host TCP stack on this explicit test wire.
            ASSERT_TRUE(m_stack->Input(netstack::PacketPath::Peer, packet));
        }
    }

    void Establish()
    {
        ASSERT_NO_FATAL_FAILURE(SendHostPackets());
        const auto schedule = LastSchedule();
        ASSERT_TRUE(schedule.has_value());
        ASSERT_EQ(schedule->Delay, std::chrono::milliseconds::zero());
        ASSERT_NO_FATAL_FAILURE(ReceivePump(schedule->RequestId));
        ASSERT_EQ(m_host->State(), netstack::StreamState::Open);
        ASSERT_NO_FATAL_FAILURE(SendHostPackets());
        m_remote.clear();
    }

    tailgate::di::Injector m_injector;
    tailgate::hosted::Client* m_client = nullptr;
    bg::manager::DataPlaneManager* m_subject = nullptr;
    netstack::Stack* m_stack = nullptr;
    std::unique_ptr<netstack::Stream> m_host;
    std::vector<std::uint8_t> m_remote;
};

TEST_F(Given_VpnDataPlane, When_HeartbeatsArriveWhileIdle_Then_NoPumpIsScheduled)
{
    m_host->Abort();
    (void)m_stack->TakeOutput(128);
    auto& time = dynamic_cast<tailgate::tests::fakes::FakeTimeProvider&>(
        m_injector.create<tailgate::base::TimeProvider&>());
    const tailgate::hosted::Frame heartbeat(tailgate::hosted::MessageType::Heartbeat, {});
    std::vector<std::vector<std::uint8_t>> local;
    bg::service::DecapsulationContext context{
        .Message = heartbeat, .Client = *m_client, .LocalOutput = local, .RemoteOutput = m_remote};
    bool scheduled = false;

    for (unsigned count = 0; count < 3; ++count)
    {
        time.Advance(std::chrono::seconds(20));
        m_subject->Decapsulate(context);
        m_subject->FlushLocal(local, m_remote);
        scheduled |= LastSchedule().has_value();
    }

    EXPECT_FALSE(scheduled);
    EXPECT_TRUE(local.empty());
    EXPECT_FALSE(m_stack->NextDeadline());
}

TEST_F(Given_VpnDataPlane, When_SynGeneratesLocalSynAck_Then_IncomingPumpCompletesHostHandshake)
{
    ASSERT_NO_FATAL_FAILURE(SendHostPackets());
    const auto schedule = LastSchedule();
    ASSERT_TRUE(schedule.has_value());
    ASSERT_EQ(schedule->Delay, std::chrono::milliseconds::zero());

    ReceivePump(schedule->RequestId);

    EXPECT_EQ(m_host->State(), netstack::StreamState::Open);
    EXPECT_FALSE(m_injector.create<bg::PacketDevice&>().HasOutput());
}

TEST_F(Given_VpnDataPlane, When_VirtualWebDavRespondsLocally_Then_PumpDeliversHttpResponse)
{
    ASSERT_NO_FATAL_FAILURE(Establish());
    const std::string request = "OPTIONS / HTTP/1.1\r\nHost: 100.100.100.100:8080\r\n\r\n";
    ASSERT_EQ(
        m_host->TryWriteSome(reinterpret_cast<const std::uint8_t*>(request.data()), request.size()),
        request.size());
    ASSERT_NO_FATAL_FAILURE(SendHostPackets());
    const auto schedule = LastSchedule();
    ASSERT_TRUE(schedule.has_value());
    ASSERT_EQ(schedule->Delay, std::chrono::milliseconds::zero());

    ReceivePump(schedule->RequestId);
    const auto bytes = m_host->TryReadSome(4096);
    const auto text = bytes ? std::string(bytes->begin(), bytes->end()) : std::string{};

    EXPECT_TRUE(text.starts_with("HTTP/1.1 200"));
    EXPECT_NE(
        text.find("Allow: OPTIONS, LOCK, DELETE, PROPPATCH, COPY, MOVE, UNLOCK, PROPFIND\r\n"),
        std::string::npos);
    EXPECT_NE(text.find("MS-Author-Via: DAV\r\n"), std::string::npos);
    EXPECT_EQ(m_host->State(), netstack::StreamState::Open);
}

} // namespace tailgate::uwp::tests
