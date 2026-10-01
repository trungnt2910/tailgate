#include <memory>
#include <string>
#include <utility>

#include <gtest/gtest.h>

#include <tailgate/crypto/Crypto.h>
#include <tailgate/wgengine/PeerProtocol.h>

#include "bg/DI.h"
#include "common/EventLoop.h"
#include "plugin/NodeContext.h"

#include "fakes/bg/manager/FakeSessionManager.h"
#include "fakes/ipn/ipnlocal/FakeLocalServices.h"

namespace
{

class Given_NodeContext : public testing::Test
{
protected:
    tailgate::wgengine::PeerIdentity Identity()
    {
        const auto key = tailgate::crypto::GeneratePrivateKey();
        return {
            .NodePrivateKey = key,
            .NodePublicKey = tailgate::crypto::X25519PublicFromPrivate(key),
            .DiscoPrivateKey = tailgate::crypto::GeneratePrivateKey(),
        };
    }

    tailgate::uwp::bg::NodeContext& Create(const std::string& profile,
                                           const tailgate::wgengine::PeerIdentity& identity)
    {
        auto& node = Root->create<tailgate::uwp::bg::NodeContext&>();
        node.Configure(profile, identity);
        return node;
    }

    tailgate::uwp::bg::PluginInjector Root = tailgate::uwp::bg::CreatePluginInjector();
};

TEST_F(Given_NodeContext, When_TransportResets_Then_AccountServicesAndProtocolArePreserved)
{
    const auto identity = Identity();
    auto& node = Create("profile", identity);
    auto& protocol = Root->create<tailgate::wgengine::PeerProtocol&>();
    protocol.Initialize(identity, {}, {});
    auto& disco = protocol.Disco();
    auto services = Root->create<std::shared_ptr<tailgate::ipn::ipnlocal::LocalServices>>();

    node.ResetTransport();
    node.Configure("profile", identity);

    EXPECT_TRUE(node.Matches("profile", identity));
    EXPECT_EQ(&Root->create<tailgate::wgengine::PeerProtocol&>().Disco(), &disco);
    EXPECT_EQ(Root->create<std::shared_ptr<tailgate::ipn::ipnlocal::LocalServices>>(), services);
    EXPECT_EQ(&Root->create<tailgate::uwp::bg::NodeContext&>(), &node);
    EXPECT_EQ(node.DataPlane().ServiceCount(), 3U);
}

TEST_F(Given_NodeContext, When_TransportResets_Then_SharedDeviceCanReopenWithoutOldPackets)
{
    auto& node = Create("profile", Identity());
    auto& engine = Root->create<tailgate::wgengine::Engine&>();
    auto& device = Root->create<tailgate::uwp::bg::PacketDevice&>();
    auto& events = Root->create<tailgate::base::EventLoop&>();
    constexpr tailgate::base::EventToken token{.Value = 7};
    ASSERT_TRUE(engine.OpenPacketDevice({.Name = {}, .ReadinessToken = token}));
    ASSERT_EQ(device.QueueInput({1, 2, 3}), tailgate::uwp::bg::PacketQueueResult::Complete);
    ASSERT_EQ(engine.WritePacket({4, 5, 6}), tailgate::wgengine::PacketWriteResult::Written);

    node.ResetTransport();
    const auto closed = !engine.PacketDeviceOpen();
    const auto reopened = engine.OpenPacketDevice({.Name = {}, .ReadinessToken = token});
    const auto input = device.TryRead(64);
    const auto output = device.DrainOutput();
    const auto pending = events.TakePostedEvents(8);

    EXPECT_TRUE(closed);
    EXPECT_TRUE(reopened);
    EXPECT_EQ(input.Result, tailgate::wgengine::tstun::DeviceIoResult::WouldBlock);
    EXPECT_TRUE(output.empty());
    EXPECT_TRUE(pending.empty());
    EXPECT_EQ(&Root->create<tailgate::wgengine::tstun::Device&>(), &device);
}

TEST_F(Given_NodeContext, When_ProfileChangesWithSameKeys_Then_RequiresAccountReset)
{
    const auto identity = Identity();
    auto& node = Create("old-profile", identity);

    const auto matches = node.Matches("new-profile", identity);

    EXPECT_FALSE(matches);
}

TEST_F(Given_NodeContext, When_KeysChangeWithinProfile_Then_RequiresAccountReset)
{
    auto& node = Create("profile", Identity());
    const auto replacement = Identity();

    const auto matches = node.Matches("profile", replacement);

    EXPECT_FALSE(matches);
}

TEST_F(Given_NodeContext, When_DiscoKeyChanges_Then_RequiresAccountReset)
{
    auto identity = Identity();
    auto& node = Create("profile", identity);
    identity.DiscoPrivateKey = tailgate::crypto::GeneratePrivateKey();

    const auto matches = node.Matches("profile", identity);

    EXPECT_FALSE(matches);
}

TEST_F(Given_NodeContext, When_AccountChanges_Then_SharedProtocolAcceptsNewIdentity)
{
    const auto oldIdentity = Identity();
    auto& node = Create("old-profile", oldIdentity);
    auto& protocol = Root->create<tailgate::wgengine::PeerProtocol&>();
    protocol.Initialize(oldIdentity, {}, {});
    const auto identity = Identity();
    tailgate::hosted::ClientConfig config;
    config.NodePrivateKey = identity.NodePrivateKey;
    config.NodePublicKey = identity.NodePublicKey;
    config.DiscoPrivateKey = identity.DiscoPrivateKey;
    config.Network.SelfAddress("192.0.2.1");

    node.Configure("new-profile", identity);
    const auto reset = !protocol.Initialized();
    const auto hello = node.HostedClient().Start(std::move(config));

    EXPECT_TRUE(reset);
    EXPECT_FALSE(hello.empty());
    EXPECT_TRUE(node.HostedClient().Active());
    EXPECT_TRUE(protocol.Initialized());
    EXPECT_TRUE(node.Matches("new-profile", identity));
}

TEST_F(Given_NodeContext, When_NodeReportsState_Then_PluginSessionReceivesIt)
{
    Root->install(
        boost::di::bind<tailgate::uwp::bg::SessionManager>.to<tailgate::uwp::tests::FakeSessionManager>());
    auto session = std::dynamic_pointer_cast<tailgate::uwp::tests::FakeSessionManager>(
        Root->create<std::shared_ptr<tailgate::uwp::bg::SessionManager>>());
    ASSERT_TRUE(session);
    auto& node = Create("profile", Identity());
    const auto generation = session->BeginConnect();

    node.DataPlane().Start(generation);
    node.DataPlane().Connect();
    node.DataPlane().Stop();
    ASSERT_EQ(session->Reports.size(), 2U);

    EXPECT_EQ(session->Reports.front().Generation, generation);
    EXPECT_EQ(session->Reports.front().Kind,
              tailgate::uwp::bg::manager::SessionEventKind::Connecting);
    EXPECT_EQ(session->Reports.back().Generation, generation);
    EXPECT_EQ(session->Reports.back().Kind, tailgate::uwp::bg::manager::SessionEventKind::Ready);
}

TEST_F(Given_NodeContext, When_ExplicitlyStopped_Then_SharedLocalServicesStop)
{
    Root->install(
        boost::di::bind<tailgate::ipn::ipnlocal::LocalServices>.to<tailgate::tests::fakes::FakeLocalServices>());
    auto services = std::dynamic_pointer_cast<tailgate::tests::fakes::FakeLocalServices>(
        Root->create<std::shared_ptr<tailgate::ipn::ipnlocal::LocalServices>>());
    ASSERT_TRUE(services);
    auto& node = Root->create<tailgate::uwp::bg::NodeContext&>();

    node.Stop();

    EXPECT_EQ(services->Stops, 1);
    EXPECT_FALSE(node.HostedClient().Active());
}

TEST_F(Given_NodeContext, When_AccountChanges_Then_SharedLocalServicesStop)
{
    Root->install(
        boost::di::bind<tailgate::ipn::ipnlocal::LocalServices>.to<tailgate::tests::fakes::FakeLocalServices>());
    auto services = std::dynamic_pointer_cast<tailgate::tests::fakes::FakeLocalServices>(
        Root->create<std::shared_ptr<tailgate::ipn::ipnlocal::LocalServices>>());
    ASSERT_TRUE(services);
    auto& node = Create("old-profile", Identity());
    const auto stops = services->Stops;

    node.Configure("new-profile", Identity());

    EXPECT_EQ(services->Stops, stops + 1);
}

} // namespace
