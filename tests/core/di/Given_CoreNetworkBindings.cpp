#include <cstddef>
#include <memory>

#include <gtest/gtest.h>

#include <tailgate/base/EventLoop.h>
#include <tailgate/base/TimeProvider.h>
#include <tailgate/crypto/Certificate.h>
#include <tailgate/crypto/Random.h>
#include <tailgate/net/http/Client.h>
#include <tailgate/types/nettype/TcpSocket.h>
#include <tailgate/types/nettype/UdpSocket.h>
#include <tailgate/wgengine/Engine.h>
#include <tailgate/wgengine/magicsock/Connection.h>
#include <tailgate/wgengine/ping/Tracker.h>

#include "fakes/di/FakeNetworkBindings.h"

namespace
{

class BindingLifetime
{
public:
    virtual ~BindingLifetime() = default;
};

class BindingLifetimeImpl final : public BindingLifetime
{
public:
    ~BindingLifetimeImpl() override
    {
        ++DestructionCount;
    }

    static inline std::size_t DestructionCount = 0;
};

} // namespace

TEST(Given_CoreNetworkBindings, When_ResolvingPrimitives_Then_InjectedFakesAreReturned)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);

    tailgate::base::EventLoop& eventLoop = injector.create<tailgate::base::EventLoop&>();
    tailgate::base::TimeProvider& timeProvider = injector.create<tailgate::base::TimeProvider&>();
    tailgate::types::nettype::UdpSocketFactory& socketFactory =
        injector.create<tailgate::types::nettype::UdpSocketFactory&>();
    tailgate::types::nettype::TcpSocketFactory& tcpSocketFactory =
        injector.create<tailgate::types::nettype::TcpSocketFactory&>();

    EXPECT_NE(dynamic_cast<tailgate::tests::fakes::FakeEventLoop*>(&eventLoop), nullptr);
    EXPECT_NE(dynamic_cast<tailgate::tests::fakes::FakeTimeProvider*>(&timeProvider), nullptr);
    EXPECT_NE(dynamic_cast<tailgate::tests::fakes::FakeUdpSocketFactory*>(&socketFactory), nullptr);
    EXPECT_NE(dynamic_cast<tailgate::tests::fakes::FakeTcpSocketFactory*>(&tcpSocketFactory),
              nullptr);
}

TEST(Given_CoreNetworkBindings, When_ResolvingCoreClassesTwice_Then_InjectorSharesInstances)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);

    const auto* firstEngine = &injector.create<tailgate::wgengine::Engine&>();
    const auto* secondEngine = &injector.create<tailgate::wgengine::Engine&>();
    const auto* firstConnection = &injector.create<tailgate::wgengine::magicsock::Connection&>();
    const auto* secondConnection = &injector.create<tailgate::wgengine::magicsock::Connection&>();
    const auto* firstPingTracker = &injector.create<tailgate::wgengine::ping::Tracker&>();
    const auto* secondPingTracker = &injector.create<tailgate::wgengine::ping::Tracker&>();

    EXPECT_EQ(firstEngine, secondEngine);
    EXPECT_EQ(firstConnection, secondConnection);
    EXPECT_EQ(firstPingTracker, secondPingTracker);
}

TEST(Given_CoreNetworkBindings, When_CreatingSeparateInjectors_Then_CoreStateDoesNotLeak)
{
    tailgate::di::Injector firstInjector;
    tailgate::di::Injector secondInjector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(firstInjector);
    tailgate::tests::fakes::InstallFakeNetworkBindings(secondInjector);

    const auto* first = &firstInjector.create<tailgate::wgengine::magicsock::Connection&>();
    const auto* second = &secondInjector.create<tailgate::wgengine::magicsock::Connection&>();

    EXPECT_NE(first, second);
}

TEST(Given_CoreNetworkBindings, When_ResolvingCoreUtilitiesTwice_Then_InjectorSharesInstances)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);

    const auto* firstCrypto = &injector.create<tailgate::crypto::Certificate&>();
    const auto* secondCrypto = &injector.create<tailgate::crypto::Certificate&>();
    const auto* firstRandom = &injector.create<tailgate::crypto::Random&>();
    const auto* secondRandom = &injector.create<tailgate::crypto::Random&>();
    const auto* firstHttp = &injector.create<tailgate::net::http::Client&>();
    const auto* secondHttp = &injector.create<tailgate::net::http::Client&>();

    EXPECT_EQ(firstCrypto, secondCrypto);
    EXPECT_EQ(firstRandom, secondRandom);
    EXPECT_EQ(firstHttp, secondHttp);
}

TEST(Given_CoreNetworkBindings, When_SharedBindingOutlivesInjector_Then_InstanceRemainsOwned)
{
    BindingLifetimeImpl::DestructionCount = 0;
    std::shared_ptr<BindingLifetime> retained;

    {
        tailgate::di::Injector injector;
        injector.InstallSingleton<BindingLifetimeImpl, BindingLifetime>();
        retained = injector.create<std::shared_ptr<BindingLifetime>>();
    }
    const bool remainedAlive = retained != nullptr && BindingLifetimeImpl::DestructionCount == 0;
    retained.reset();

    EXPECT_TRUE(remainedAlive);
    EXPECT_EQ(BindingLifetimeImpl::DestructionCount, 1U);
}
