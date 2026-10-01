#include <memory>
#include <system_error>

#include <gtest/gtest.h>

#include "bg/DI.h"
#include "common/EventLoop.h"
#include "plugin/NativeConnection.h"

#include "fakes/ipn/ipnlocal/FakeLocalServices.h"

namespace
{

class Given_NativeConnection : public testing::Test
{
protected:
    tailgate::uwp::bg::PluginInjector CreateInjector()
    {
        auto injector = tailgate::uwp::bg::CreatePluginInjector();
        injector->install(
            boost::di::bind<tailgate::ipn::ipnlocal::LocalServices>.to<tailgate::tests::fakes::FakeLocalServices>());
        Services = std::dynamic_pointer_cast<tailgate::tests::fakes::FakeLocalServices>(
            injector->create<std::shared_ptr<tailgate::ipn::ipnlocal::LocalServices>>());
        Events = injector->create<std::shared_ptr<tailgate::base::EventLoop>>();
        Protocol = injector->create<std::shared_ptr<tailgate::wgengine::PeerProtocol>>();
        return injector;
    }

    std::shared_ptr<tailgate::base::EventLoop> Events;
    std::shared_ptr<tailgate::wgengine::PeerProtocol> Protocol;
    std::shared_ptr<tailgate::tests::fakes::FakeLocalServices> Services;
};

TEST_F(Given_NativeConnection, When_PluginIsCreated_Then_NodeServicesAndProtocolAreShared)
{
    auto injector = CreateInjector();

    auto& protocol = injector->create<tailgate::wgengine::PeerProtocol&>();
    auto& services = injector->create<tailgate::ipn::ipnlocal::LocalServices&>();
    auto& events = injector->create<tailgate::base::EventLoop&>();

    EXPECT_EQ(&protocol, Protocol.get());
    EXPECT_EQ(&services, Services.get());
    EXPECT_EQ(&events, Events.get());
}

TEST_F(Given_NativeConnection, When_NativeDeviceReceivesPacket_Then_WakesSharedNodeEventLoop)
{
    auto injector = CreateInjector();
    auto& device = injector->create<tailgate::uwp::bg::PacketDevice&>();
    constexpr tailgate::base::EventToken token{.Value = 7};
    ASSERT_TRUE(device.Open({.Name = {}, .ReadinessToken = token}));

    const auto queued = device.QueueInput({1, 2, 3});
    const auto events = Events->TakePostedEvents(8);
    ASSERT_EQ(events.size(), 1U);

    EXPECT_EQ(queued, tailgate::uwp::bg::PacketQueueResult::Complete);
    EXPECT_EQ(events.front().Token, token);
    EXPECT_TRUE(tailgate::base::HasReadiness(events.front().Readiness,
                                             tailgate::base::EventReadiness::Readable));
}

TEST_F(Given_NativeConnection, When_SelectedAdapterIsMissing_Then_NativeStartupFails)
{
    tailgate::uwp::bg::NativeConnection connection(
        CreateInjector(), "missing-test-adapter", {}, {});
    std::error_code error;

    try
    {
        (void)connection.Open({});
    }
    catch (const std::system_error& failure)
    {
        error = failure.code();
    }

    EXPECT_EQ(error, std::errc::network_unreachable);
    EXPECT_EQ(Services->Stops, 0);
}

} // namespace
