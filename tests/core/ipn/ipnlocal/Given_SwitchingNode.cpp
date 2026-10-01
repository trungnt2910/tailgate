#include <gtest/gtest.h>

#include <tailgate/ipn/ipnlocal/SwitchingNode.h>
#include <tailgate/wgengine/PeerProtocol.h>

#include "fakes/derp/FakeConnection.h"
#include "fakes/di/FakeNetworkBindings.h"
#include "fakes/hosted/FakeTcpSocket.h"
#include "fakes/ipn/ipnlocal/FakeLocalServices.h"

namespace tailgate
{
namespace
{

using ipn::ipnlocal::DerpTransportFactory;
using ipn::ipnlocal::DnsForwarder;
using ipn::ipnlocal::HostedNode;
using ipn::ipnlocal::NativeNode;
using ipn::ipnlocal::NodeEvents;
using ipn::ipnlocal::NodeMode;
using ipn::ipnlocal::SwitchingNode;
using ipn::ipnlocal::TransitionPhase;
constexpr base::EventToken DeviceToken{.Value = 1};

class Given_SwitchingNode : public testing::Test, public DerpTransportFactory
{
protected:
    Given_SwitchingNode()
    {
        tests::fakes::InstallFakeNetworkBindings(Injector);
        Config.NodePrivateKey.front() = 7;
        Config.DiscoPrivateKey.front() = 11;
        Config.NodePublicKey = crypto::X25519PublicFromPrivate(Config.NodePrivateKey);
        Config.Network.Domain("example.ts.net");
        Config.Network.SelfNodeId(42);
        Config.Network.SelfAddress("100.64.0.1");
        Config.Network.SelfName("self.example.ts.net");
        Config.Network.SelfKey("nodekey:" + crypto::BytesToHex(Config.NodePublicKey.data(),
                                                               Config.NodePublicKey.size()));
        Config.Network.DerpRegion(1);
        Config.Network.DerpHost("derp.example.com");
        auto& session = Injector.create<wgengine::Session&>();
        auto& engine = Injector.create<wgengine::Engine&>();
        auto& dns = Injector.create<DnsForwarder&>();
        auto& pings = Injector.create<wgengine::ping::Tracker&>();
        Native = std::make_unique<NativeNode>(session,
                                              engine,
                                              Injector.create<wgengine::magicsock::Connection&>(),
                                              Services,
                                              dns,
                                              pings,
                                              Time(),
                                              *this);
        Native->Start(
            Config.Network,
            {.NodePrivateKey = Config.NodePrivateKey,
             .NodePublicKey = Config.NodePublicKey,
             .DiscoPrivateKey = Config.DiscoPrivateKey,
             .AdvertisedEndpoint = {},
             .HomeDerpRegion = 1,
             .Peers = {},
             .ExitNode = {}},
            {.Name = "test", .ReadinessToken = DeviceToken},
            {.BindEndpoint = {}, .NetworkInterface = "adapter-a", .ReadinessToken = {.Value = 2}},
            std::nullopt,
            false);
        Hosted = std::make_unique<HostedNode>(Injector.create<hosted::Client&>(),
                                              session,
                                              engine,
                                              Services,
                                              dns,
                                              pings,
                                              Time(),
                                              Injector.create<hosted::Dns&>(),
                                              Injector.create<hosted::Recovery&>());
        hosted::ConnectionOptions reconnect;
        reconnect.Client = Config;
        reconnect.Socket.ConnectAddress = "192.0.2.1";
        reconnect.Socket.Service = "443";
        Hosted->Start({.Stream = std::make_unique<tests::fakes::FakeTcpSocket>(Socket),
                       .RelayPublicKey = {},
                       .RelaySession = {"example.ts.net", "relay", "192.0.2.1", {}},
                       .FrameDecoder = {},
                       .Configuration = Config,
                       .Reconnect = reconnect},
                      {.Name = "test", .ReadinessToken = DeviceToken},
                      {},
                      "relay");
        Preparation = std::make_unique<hosted::Recovery>(
            Injector.create<types::nettype::TcpSocketFactory&>(), PreparationEvents, Time());
        Subject = std::make_unique<SwitchingNode>(
            *Native,
            *Hosted,
            *Preparation,
            Time(),
            NodeMode::Hosted,
            wgengine::tstun::DeviceOptions{.Name = "test", .ReadinessToken = DeviceToken},
            "");
        Events().Next.Status = base::EventWaitStatus::Woken;
        Socket->Incoming.push_back(hosted::EncodeMapAcknowledgement(1).Encode());
        (void)Wait();
    }

    void SetNetworkInterface(const std::string&) override
    {
    }

    std::unique_ptr<derp::Connection>
    Create(int, const std::string&, bool, std::size_t, bool enabled) override
    {
        auto derp = std::make_unique<tests::fakes::derp::FakeConnection>(
            base::EventToken{.Value = 3}, derp::DerpClient::Packet{});
        Derp = derp.get();
        derp->SetEnabled(enabled);
        return derp;
    }

    NodeEvents Wait()
    {
        return Subject->Wait(16, 16, 4096);
    }

    void Reply(hosted::DelegationStatus status)
    {
        (void)Wait();
        hosted::Decoder decoder;
        decoder.Feed(Socket->Written);
        Socket->Written.clear();
        std::optional<hosted::DelegationRequest> request;
        while (const auto frame = decoder.Next())
        {
            if (auto decoded = hosted::DecodeDelegationRequest(*frame))
            {
                request = std::move(decoded);
            }
        }
        ASSERT_TRUE(request);
        Socket->Incoming.push_back(
            hosted::EncodeDelegation(hosted::DelegationReply{.Generation = request->Generation,
                                                             .RequestId = request->RequestId,
                                                             .MapRevision = request->MapRevision,
                                                             .Status = status})
                .Encode());
        (void)Wait();
    }

    void Release()
    {
        ASSERT_TRUE(Subject->RequestMode(NodeMode::Native));
        (void)Wait();
        Reply(hosted::DelegationStatus::Prepared);
        Reply(hosted::DelegationStatus::Released);
    }

    tests::fakes::FakeTimeProvider& Time()
    {
        return dynamic_cast<tests::fakes::FakeTimeProvider&>(
            Injector.create<base::TimeProvider&>());
    }

    tests::fakes::FakeEventLoop& Events()
    {
        return dynamic_cast<tests::fakes::FakeEventLoop&>(Injector.create<base::EventLoop&>());
    }

    tests::fakes::FakeDevice& Device()
    {
        return Injector.create<tests::fakes::FakeDevice&>();
    }

    di::Injector Injector;
    tests::fakes::FakeLocalServices Services;
    tests::fakes::FakeEventLoop PreparationEvents;
    hosted::ClientConfig Config;
    tests::fakes::derp::FakeConnection* Derp = nullptr;
    std::shared_ptr<tests::fakes::FakeTcpSocketState> Socket =
        std::make_shared<tests::fakes::FakeTcpSocketState>();
    std::unique_ptr<NativeNode> Native;
    std::unique_ptr<HostedNode> Hosted;
    std::unique_ptr<hosted::Recovery> Preparation;
    std::unique_ptr<SwitchingNode> Subject;
};

TEST_F(Given_SwitchingNode, When_StartingHosted_Then_NativeDerpDoesNotCompeteForNodeKey)
{
    const auto mode = Subject->Transition();

    EXPECT_EQ(mode.Effective, NodeMode::Hosted);
    EXPECT_FALSE(Derp->Enabled);
    EXPECT_TRUE(Device().Opened);
    EXPECT_FALSE(Device().Closed);
}

TEST_F(Given_SwitchingNode, When_PreparingNative_Then_LocalServicesProgressBeforeOwnershipRelease)
{
    ASSERT_TRUE(Subject->RequestMode(NodeMode::Native));
    Services.Output.push_back({.Peer = {}, .Bytes = {1, 2, 3}, .ForwardFromHost = false});

    (void)Wait();

    EXPECT_EQ(Device().Written, (std::vector<std::vector<std::uint8_t>>{{1, 2, 3}}));
    EXPECT_FALSE(Derp->Enabled);
    EXPECT_EQ(Subject->Transition().Effective, NodeMode::Hosted);
    EXPECT_EQ(Services.Stops, 0);
}

TEST_F(Given_SwitchingNode, When_ReleasedNativeBecomesReady_Then_ReusesRouterDeviceAndLocalServices)
{
    const auto* router = &Injector.create<wgengine::PeerProtocol&>().Router();

    Release();
    (void)Wait();

    EXPECT_TRUE(Derp->Enabled);
    EXPECT_EQ(Subject->Transition().Effective, NodeMode::Native);
    EXPECT_EQ(&Injector.create<wgengine::PeerProtocol&>().Router(), router);
    EXPECT_FALSE(Device().Closed);
    EXPECT_EQ(Services.Stops, 0);
}

TEST_F(Given_SwitchingNode, When_TransitionCommits_Then_RelayClosesOnlyAfterDrain)
{
    Release();
    (void)Wait();
    Reply(hosted::DelegationStatus::Committed);

    const auto before = Socket->Closed;
    Time().Advance(std::chrono::milliseconds(400));
    (void)Wait();

    EXPECT_FALSE(before);
    EXPECT_TRUE(Socket->Closed);
    EXPECT_EQ(Subject->Transition().Phase, TransitionPhase::Idle);
    EXPECT_FALSE(Device().Closed);
    EXPECT_EQ(Services.Stops, 0);
}

TEST_F(Given_SwitchingNode, When_AllUnderlaysDisappear_Then_LocalServicesContinueOffline)
{
    Subject->ChangeNetwork(std::nullopt);
    Services.Output.push_back({.Peer = {}, .Bytes = {4, 5}, .ForwardFromHost = false});

    (void)Wait();

    EXPECT_EQ(Device().Written, (std::vector<std::vector<std::uint8_t>>{{4, 5}}));
    EXPECT_FALSE(Derp->Enabled);
    EXPECT_FALSE(Hosted->HasTransport());
    EXPECT_EQ(Services.Stops, 0);
}

TEST_F(Given_SwitchingNode, When_NativeReturnsToHosted_Then_ReacquiresOnlyAfterNativeRelease)
{
    Release();
    (void)Wait();
    Reply(hosted::DelegationStatus::Committed);
    Time().Advance(std::chrono::milliseconds(400));
    (void)Wait();
    ASSERT_EQ(Subject->Transition().Phase, TransitionPhase::Idle);
    ASSERT_EQ(Subject->Transition().Effective, NodeMode::Native);
    Socket = std::make_shared<tests::fakes::FakeTcpSocketState>();
    auto& factory = dynamic_cast<tests::fakes::FakeTcpSocketFactory&>(
        Injector.create<types::nettype::TcpSocketFactory&>());
    factory.Open = [state = Socket](const auto&)
    {
        return std::make_unique<tests::fakes::hosted::FakeTcpSocket>(
            crypto::GeneratePrivateKey(), crypto::GeneratePrivateKey(), false, state);
    };
    hosted::ConnectionOptions relay;
    relay.Client = Config;
    relay.Socket.ConnectAddress = "192.0.2.1";
    relay.Socket.Service = "443";
    relay.Socket.NonBlockingAfterConnect = true;
    relay.HttpHost = "relay.example.com";
    relay.Hostname = "self";
    const auto* router = &Injector.create<wgengine::PeerProtocol&>().Router();

    const auto accepted = Subject->RequestMode(NodeMode::Hosted, relay);
    const auto nativeDuringPreparation = Derp->Enabled;
    Time().Advance(std::chrono::seconds(1));
    (void)Wait();
    PreparationEvents.WaitForWake();
    (void)Wait();
    const auto nativeBeforeMapAck = Derp->Enabled;
    Socket->Incoming.push_back(hosted::EncodeMapAcknowledgement(1).Encode());
    (void)Wait();
    Reply(hosted::DelegationStatus::Prepared);
    const auto selectedBeforeReady = Subject->Transition().Effective;
    Reply(hosted::DelegationStatus::Ready);
    Reply(hosted::DelegationStatus::Committed);
    Time().Advance(std::chrono::milliseconds(400));
    (void)Wait();

    EXPECT_TRUE(accepted);
    EXPECT_TRUE(nativeDuringPreparation);
    EXPECT_FALSE(nativeBeforeMapAck);
    EXPECT_EQ(selectedBeforeReady, NodeMode::Native);
    EXPECT_EQ(Subject->Transition().Effective, NodeMode::Hosted);
    EXPECT_EQ(Subject->Transition().Phase, TransitionPhase::Idle);
    EXPECT_FALSE(Derp->Enabled);
    EXPECT_TRUE(Hosted->HasTransport());
    EXPECT_EQ(&Injector.create<wgengine::PeerProtocol&>().Router(), router);
    EXPECT_FALSE(Device().Closed);
    EXPECT_EQ(Services.Stops, 0);
}

TEST_F(Given_SwitchingNode, When_HostPolicyChangesDuringPreparation_Then_CancelsHandoffExplicitly)
{
    ASSERT_TRUE(Subject->RequestMode(NodeMode::Native));

    Subject->CancelTransition(ipn::ipnlocal::TransitionFailure::PolicyChanged);
    (void)Wait();

    EXPECT_EQ(Subject->Transition().Phase, TransitionPhase::Failed);
    EXPECT_EQ(Subject->Transition().Failure, ipn::ipnlocal::TransitionFailure::PolicyChanged);
    EXPECT_EQ(Subject->Transition().Effective, NodeMode::Hosted);
    EXPECT_FALSE(Derp->Enabled);
    EXPECT_FALSE(Device().Closed);
    EXPECT_EQ(Services.Stops, 0);
}

} // namespace

} // namespace tailgate
