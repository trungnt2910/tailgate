#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/base/EventLoop.h>
#include <tailgate/net/Endpoint.h>
#include <tailgate/types/nettype/UdpSocket.h>

#include "event/EventRegistry.h"
#include "impl/EventLoop.h"
#include "impl/UdpSocketFactory.h"

namespace
{

constexpr tailgate::net::Ipv4Address Loopback =
    tailgate::net::Ipv4Address::FromOctets(127, 0, 0, 1);
constexpr tailgate::net::Ipv4Address Broadcast =
    tailgate::net::Ipv4Address::FromOctets(255, 255, 255, 255);
constexpr tailgate::base::EventToken ReceiverToken{.Value = 1};
constexpr std::uint16_t TestDestinationPort = 41641;
constexpr std::size_t MaximumEvents = 4;
constexpr std::size_t MaximumDatagramSize = 4096;

struct DatagramObservation
{
    tailgate::types::nettype::SocketIoResult SendResult =
        tailgate::types::nettype::SocketIoResult::Closed;
    tailgate::base::EventWaitResult WaitResult;
    tailgate::types::nettype::UdpReceiveResult ReceiveResult;
};

} // namespace

TEST(Given_LinuxUdpSocketFactory,
     When_UdpSocketIsOpened_Then_RequestedAddressAndEphemeralPortAreBound)
{
    auto eventRegistry = std::make_shared<tailgate::linux_frontend::event::EventRegistry>();
    tailgate::linux_frontend::impl::UdpSocketFactory factory(eventRegistry);

    const std::unique_ptr<tailgate::types::nettype::UdpSocket> socket =
        factory.OpenUdpSocket(tailgate::types::nettype::UdpSocketOptions{
            .BindEndpoint = tailgate::net::Endpoint(Loopback, 0),
            .NetworkInterface = std::nullopt,
            .ReadinessToken = {},
        });

    ASSERT_NE(socket, nullptr);
    EXPECT_EQ(socket->LocalEndpoint().Address(), Loopback);
    EXPECT_NE(socket->LocalEndpoint().Port(), 0);
}

TEST(Given_LinuxUdpSocketFactory, When_DatagramArrives_Then_ReadinessAndPayloadAreReturned)
{
    auto eventRegistry = std::make_shared<tailgate::linux_frontend::event::EventRegistry>();
    tailgate::linux_frontend::impl::EventLoop eventLoop(eventRegistry);
    tailgate::linux_frontend::impl::UdpSocketFactory factory(eventRegistry);
    const std::unique_ptr<tailgate::types::nettype::UdpSocket> receiver =
        factory.OpenUdpSocket(tailgate::types::nettype::UdpSocketOptions{
            .BindEndpoint = tailgate::net::Endpoint(Loopback, 0),
            .NetworkInterface = std::nullopt,
            .ReadinessToken = ReceiverToken,
        });
    const std::unique_ptr<tailgate::types::nettype::UdpSocket> sender =
        factory.OpenUdpSocket(tailgate::types::nettype::UdpSocketOptions{
            .BindEndpoint = tailgate::net::Endpoint(Loopback, 0),
            .NetworkInterface = std::nullopt,
            .ReadinessToken = {},
        });
    const std::vector<std::uint8_t> payload{1, 2, 3};

    const auto observe = [&]()
    {
        DatagramObservation result;
        result.SendResult = sender->TrySendTo(receiver->LocalEndpoint(), payload);
        result.WaitResult = eventLoop.Wait(MaximumEvents);
        result.ReceiveResult = receiver->TryReceive(MaximumDatagramSize);
        return result;
    };
    const DatagramObservation observation = observe();

    ASSERT_EQ(observation.WaitResult.Events.size(), 1U);
    EXPECT_EQ(observation.SendResult, tailgate::types::nettype::SocketIoResult::Complete);
    EXPECT_EQ(observation.WaitResult.Status, tailgate::base::EventWaitStatus::Events);
    EXPECT_EQ(observation.WaitResult.Events.front().Token, ReceiverToken);
    EXPECT_TRUE(tailgate::base::HasReadiness(observation.WaitResult.Events.front().Readiness,
                                             tailgate::base::EventReadiness::Readable));
    EXPECT_EQ(observation.ReceiveResult.Result, tailgate::types::nettype::SocketIoResult::Complete);
    EXPECT_EQ(observation.ReceiveResult.Datagram.Payload, payload);
    EXPECT_EQ(observation.ReceiveResult.Datagram.Source, sender->LocalEndpoint());
}

TEST(Given_LinuxUdpSocketFactory, When_FactoryIsDestroyed_Then_OpenSocketRetainsItsEventRegistry)
{
    auto eventRegistry = std::make_shared<tailgate::linux_frontend::event::EventRegistry>();
    std::weak_ptr<tailgate::linux_frontend::event::EventRegistry> eventRegistryLifetime =
        eventRegistry;
    std::unique_ptr<tailgate::types::nettype::UdpSocket> socket;
    {
        tailgate::linux_frontend::impl::UdpSocketFactory factory(eventRegistry);
        socket = factory.OpenUdpSocket(tailgate::types::nettype::UdpSocketOptions{
            .BindEndpoint = tailgate::net::Endpoint(Loopback, 0),
            .NetworkInterface = std::nullopt,
            .ReadinessToken = ReceiverToken,
        });
    }

    eventRegistry.reset();

    ASSERT_NE(socket, nullptr);
    EXPECT_FALSE(eventRegistryLifetime.expired());
}

TEST(Given_LinuxUdpSocketFactory, When_DestinationIsUnavailable_Then_TypedResultIsReturned)
{
    auto eventRegistry = std::make_shared<tailgate::linux_frontend::event::EventRegistry>();
    tailgate::linux_frontend::impl::UdpSocketFactory factory(eventRegistry);
    const std::unique_ptr<tailgate::types::nettype::UdpSocket> socket =
        factory.OpenUdpSocket(tailgate::types::nettype::UdpSocketOptions{
            .BindEndpoint = tailgate::net::Endpoint(Loopback, 0),
            .NetworkInterface = std::nullopt,
            .ReadinessToken = {},
        });
    ASSERT_NE(socket, nullptr);

    const tailgate::types::nettype::SocketIoResult result =
        socket->TrySendTo(tailgate::net::Endpoint(Broadcast, TestDestinationPort), {1, 2, 3});

    EXPECT_EQ(result, tailgate::types::nettype::SocketIoResult::Unavailable);
}
