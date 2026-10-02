#include <memory>

#include <gtest/gtest.h>

#include <tailgate/base/TimeProvider.h>
#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/ClientSession.h>
#include <tailgate/types/nettype/TcpSocket.h>
#include <tailgate/wgengine/tstun/Device.h>

#include "bg/DI.h"
#include "bg/manager/ProfileRecoveryManager.h"
#include "bg/tstun/PacketDevice.h"
#include "common/TcpPortReservationFactory.h"
#include "common/TcpSocketFactory.h"

TEST(Given_UwpBackgroundBindings, When_ResolvingTimeProvider_Then_ProductionGraphProvidesClock)
{
    auto injector = tailgate::uwp::bg::CreatePluginInjector();

    const auto clock = injector->create<std::shared_ptr<tailgate::base::TimeProvider>>();

    EXPECT_NE(clock, nullptr);
}

TEST(Given_UwpBackgroundBindings, When_ResolvingServiceTwice_Then_ProductionGraphIsScoped)
{
    auto injector = tailgate::uwp::bg::CreatePluginInjector();

    const auto* first = &injector->create<tailgate::uwp::bg::PingService&>();
    const auto* second = &injector->create<tailgate::uwp::bg::PingService&>();
    const auto* firstCore = &injector->create<tailgate::hosted::Client&>();
    const auto* secondCore = &injector->create<tailgate::hosted::Client&>();
    const auto* firstSession = &injector->create<tailgate::hosted::ClientSession&>();
    const auto* secondSession = &injector->create<tailgate::hosted::ClientSession&>();
    const auto* abstractDevice = &injector->create<tailgate::wgengine::tstun::Device&>();
    const auto* concreteDevice = &injector->create<tailgate::uwp::bg::PacketDevice&>();

    EXPECT_EQ(first, second);
    EXPECT_EQ(firstCore, secondCore);
    EXPECT_EQ(firstSession, secondSession);
    EXPECT_EQ(abstractDevice, concreteDevice);
}

TEST(Given_UwpBackgroundBindings, When_ResolvingTcpFactory_Then_GenericSocketsUseThePlatformDefault)
{
    auto injector = tailgate::uwp::bg::CreatePluginInjector();

    auto* abstractFactory = &injector->create<tailgate::types::nettype::TcpSocketFactory&>();
    auto* concreteFactory = &injector->create<tailgate::uwp::TcpSocketFactory&>();

    EXPECT_EQ(abstractFactory,
              static_cast<tailgate::types::nettype::TcpSocketFactory*>(concreteFactory));
}

TEST(Given_UwpBackgroundBindings, When_ResolvingPortReservations_Then_CoreUsesThePlatformFactory)
{
    auto injector = tailgate::uwp::bg::CreatePluginInjector();

    auto* abstractFactory =
        &injector->create<tailgate::types::nettype::TcpPortReservationFactory&>();
    auto* concreteFactory = &injector->create<tailgate::uwp::TcpPortReservationFactory&>();

    EXPECT_EQ(abstractFactory,
              static_cast<tailgate::types::nettype::TcpPortReservationFactory*>(concreteFactory));
}

TEST(Given_UwpBackgroundBindings, When_ResolvingRecoveryManager_Then_SharedWithinOnePluginOnly)
{
    auto firstGraph = tailgate::uwp::bg::CreatePluginInjector();
    auto secondGraph = tailgate::uwp::bg::CreatePluginInjector();
    using tailgate::uwp::bg::manager::ProfileRecoveryManager;

    const auto* plugin = &firstGraph->create<ProfileRecoveryManager&>();
    const auto* dispatcher = &firstGraph->create<ProfileRecoveryManager&>();
    const auto* independent = &secondGraph->create<ProfileRecoveryManager&>();

    EXPECT_EQ(plugin, dispatcher);
    EXPECT_NE(plugin, independent);
}
