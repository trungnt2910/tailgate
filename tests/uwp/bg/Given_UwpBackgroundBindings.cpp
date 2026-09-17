#include <memory>

#include <gtest/gtest.h>

#include <tailgate/base/TimeProvider.h>
#include <tailgate/hosted/Client.h>
#include <tailgate/hosted/ClientSession.h>
#include <tailgate/types/nettype/TcpSocket.h>
#include <tailgate/wgengine/tstun/Device.h>

#include "common/TcpPortReservationFactory.h"
#include "common/TcpSocketFactory.h"

#include "bg/DI.h"
#include "bg/tstun/PacketDevice.h"

TEST(Given_UwpBackgroundBindings, When_ResolvingTimeProvider_Then_ProductionGraphProvidesClock)
{
    auto injector = tailgate::uwp::bg::CreateRs2PluginInjector();

    const auto clock = injector->create<std::shared_ptr<tailgate::base::TimeProvider>>();

    EXPECT_NE(clock, nullptr);
}

TEST(Given_UwpBackgroundBindings, When_ResolvingServiceTwice_Then_ProductionGraphIsScoped)
{
    auto injector = tailgate::uwp::bg::CreateRs2PluginInjector();

    const auto* first = &injector->create<tailgate::uwp::bg::NetworkService&>();
    const auto* second = &injector->create<tailgate::uwp::bg::NetworkService&>();
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
    auto injector = tailgate::uwp::bg::CreateRs2PluginInjector();

    auto* abstractFactory = &injector->create<tailgate::types::nettype::TcpSocketFactory&>();
    auto* concreteFactory = &injector->create<tailgate::uwp::TcpSocketFactory&>();

    EXPECT_EQ(abstractFactory,
              static_cast<tailgate::types::nettype::TcpSocketFactory*>(concreteFactory));
}

TEST(Given_UwpBackgroundBindings, When_ResolvingPortReservations_Then_CoreUsesThePlatformFactory)
{
    auto injector = tailgate::uwp::bg::CreateRs2PluginInjector();

    auto* abstractFactory =
        &injector->create<tailgate::types::nettype::TcpPortReservationFactory&>();
    auto* concreteFactory = &injector->create<tailgate::uwp::TcpPortReservationFactory&>();

    EXPECT_EQ(abstractFactory,
              static_cast<tailgate::types::nettype::TcpPortReservationFactory*>(concreteFactory));
}
