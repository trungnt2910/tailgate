#include <chrono>
#include <memory>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/wgengine/magicsock/Bind.h>

#include "wgengine/magicsock/impl/ConnectionImpl.h"

#include "common/EventLoop.h"
#include "common/NetworkAdapter.h"
#include "common/TcpSocketFactory.h"
#include "common/TimeProvider.h"
#include "common/UdpSocketFactory.h"

namespace
{

using tailgate::types::nettype::SocketIoResult;
using tailgate::types::nettype::UdpSocket;
using tailgate::types::nettype::UdpSocketOptions;
constexpr auto TestTimeout = std::chrono::seconds(3);
constexpr std::size_t MaximumEvents = 8;
constexpr std::size_t MaximumPacketSize = 4096;

class Given_UwpUdpSocketFactory : public testing::Test
{
protected:
    std::unique_ptr<UdpSocket> Open(std::uint64_t token)
    {
        UdpSocketOptions options;
        options.BindEndpoint =
            tailgate::net::Endpoint(tailgate::net::Ipv4Address::FromOctets(127, 0, 0, 1), 0);
        options.ReadinessToken.Value = token;
        return m_factory.OpenUdpSocket(options);
    }

    bool WaitBound(UdpSocket& socket)
    {
        const auto deadline = m_time.After(TestTimeout);
        while (socket.LocalEndpoint().Port() == 0)
        {
            if (m_events->Wait(*deadline, MaximumEvents).Status ==
                tailgate::base::EventWaitStatus::DeadlineReached)
            {
                return false;
            }
        }
        return true;
    }

    tailgate::types::nettype::UdpReceiveResult Receive(UdpSocket& socket)
    {
        const auto deadline = m_time.After(TestTimeout);
        for (;;)
        {
            auto packet = socket.TryReceive(MaximumPacketSize);
            if (packet.Result != SocketIoResult::WouldBlock)
            {
                return packet;
            }
            if (m_events->Wait(*deadline, MaximumEvents).Status ==
                tailgate::base::EventWaitStatus::DeadlineReached)
            {
                return packet;
            }
        }
    }

    std::shared_ptr<tailgate::uwp::EventLoop> m_events =
        std::make_shared<tailgate::uwp::EventLoop>();
    tailgate::uwp::TimeProvider m_time;
    tailgate::uwp::UdpSocketFactory m_factory{m_events};
};

TEST_F(Given_UwpUdpSocketFactory,
       When_OneSocketSendsToMultiplePeers_Then_DatagramsRetainTheirSources)
{
    auto sender = Open(1);
    auto first = Open(2);
    auto second = Open(3);
    ASSERT_TRUE(WaitBound(*sender));
    ASSERT_TRUE(WaitBound(*first));
    ASSERT_TRUE(WaitBound(*second));
    const std::vector<std::uint8_t> firstPayload{1, 2, 3};
    const std::vector<std::uint8_t> secondPayload{4, 5, 6};

    const auto firstSent = sender->TrySendTo(first->LocalEndpoint(), firstPayload);
    const auto secondSent = sender->TrySendTo(second->LocalEndpoint(), secondPayload);
    const auto firstReceived = Receive(*first);
    const auto secondReceived = Receive(*second);
    const auto replySent = second->TrySendTo(sender->LocalEndpoint(), secondPayload);
    const auto reply = Receive(*sender);

    EXPECT_EQ(firstSent, SocketIoResult::Complete);
    EXPECT_EQ(secondSent, SocketIoResult::Complete);
    EXPECT_EQ(replySent, SocketIoResult::Complete);
    EXPECT_EQ(firstReceived.Result, SocketIoResult::Complete);
    EXPECT_EQ(secondReceived.Result, SocketIoResult::Complete);
    EXPECT_EQ(reply.Result, SocketIoResult::Complete);
    EXPECT_EQ(firstReceived.Datagram.Payload, firstPayload);
    EXPECT_EQ(secondReceived.Datagram.Payload, secondPayload);
    EXPECT_EQ(reply.Datagram.Payload, secondPayload);
    EXPECT_EQ(firstReceived.Datagram.Source, sender->LocalEndpoint());
    EXPECT_EQ(secondReceived.Datagram.Source, sender->LocalEndpoint());
    EXPECT_EQ(reply.Datagram.Source, second->LocalEndpoint());
}

TEST_F(Given_UwpUdpSocketFactory, When_ClosedDuringSetup_Then_SendsAndReadsReportClosed)
{
    auto socket = Open(1);
    const auto destination =
        tailgate::net::Endpoint(tailgate::net::Ipv4Address::FromOctets(127, 0, 0, 1), 12345);

    socket->Close();
    const auto sent = socket->TrySendTo(destination, {1});
    const auto received = socket->TryReceive(MaximumPacketSize);

    EXPECT_EQ(sent, SocketIoResult::Closed);
    EXPECT_EQ(received.Result, SocketIoResult::Closed);
}

TEST_F(Given_UwpUdpSocketFactory, When_SharedBootstrapBinds_Then_ReturnsUsableDatagramEndpoint)
{
    tailgate::wgengine::magicsock::impl::ConnectionImpl connection(m_factory, m_time);
    UdpSocketOptions options;
    options.BindEndpoint =
        tailgate::net::Endpoint(tailgate::net::Ipv4Address::FromOctets(127, 0, 0, 1), 0);
    options.ReadinessToken.Value = 1;
    auto sender = Open(2);
    ASSERT_TRUE(WaitBound(*sender));
    const std::vector<std::uint8_t> payload{1, 2, 3};

    const auto local =
        tailgate::wgengine::magicsock::Bind(connection, options, *m_events, m_time, TestTimeout);
    const auto sent = sender->TrySendTo(local, payload);
    const auto deadline = m_time.After(TestTimeout);
    tailgate::wgengine::magicsock::Connection::EventResult received;
    while (received.Datagrams.empty())
    {
        const auto waited = m_events->Wait(*deadline, MaximumEvents);
        for (const auto& event : m_events->TakePostedEvents(MaximumEvents))
        {
            const auto result = connection.ProcessEvent(event, MaximumEvents, MaximumPacketSize);
            received.Datagrams.insert(
                received.Datagrams.end(), result.Datagrams.begin(), result.Datagrams.end());
        }
        if (waited.Status == tailgate::base::EventWaitStatus::DeadlineReached)
        {
            break;
        }
    }
    ASSERT_EQ(received.Datagrams.size(), 1U);

    EXPECT_NE(local.Port(), 0);
    EXPECT_EQ(local.Address(), options.BindEndpoint.Address());
    EXPECT_EQ(sent, SocketIoResult::Complete);
    EXPECT_EQ(received.Datagrams.front().Payload, payload);
    EXPECT_EQ(received.Datagrams.front().Source, sender->LocalEndpoint());
}

TEST_F(Given_UwpUdpSocketFactory, When_SharedBootstrapCannotBindAdapter_Then_ClosesConnection)
{
    tailgate::wgengine::magicsock::impl::ConnectionImpl connection(m_factory, m_time);
    UdpSocketOptions options;
    options.NetworkInterface = "missing-test-adapter";
    options.ReadinessToken.Value = 1;
    std::error_code failure;

    try
    {
        (void)tailgate::wgengine::magicsock::Bind(
            connection, options, *m_events, m_time, TestTimeout);
    }
    catch (const std::system_error& error)
    {
        failure = error.code();
    }

    EXPECT_EQ(failure, std::errc::network_unreachable);
    EXPECT_FALSE(connection.LocalEndpoint());
}

TEST_F(Given_UwpUdpSocketFactory,
       When_SelectedAdapterIsMissing_Then_FailureDoesNotUseAnotherAdapter)
{
    UdpSocketOptions options;
    options.NetworkInterface = "missing-test-adapter";
    options.ReadinessToken.Value = 1;
    const auto deadline = m_time.After(TestTimeout);

    auto socket = m_factory.OpenUdpSocket(options);
    const auto waited = m_events->Wait(*deadline, MaximumEvents);
    const auto events = m_events->TakePostedEvents(MaximumEvents);
    const auto sent = socket->TrySendTo({}, {1});
    ASSERT_EQ(events.size(), 1U);

    EXPECT_EQ(waited.Status, tailgate::base::EventWaitStatus::Woken);
    EXPECT_TRUE(tailgate::base::HasReadiness(events.front().Readiness,
                                             tailgate::base::EventReadiness::Error));
    EXPECT_EQ(sent, SocketIoResult::Unavailable);
}

TEST(Given_UwpTcpSocketFactory, When_SelectedAdapterIsMissing_Then_ConnectionDoesNotUseDefaultRoute)
{
    tailgate::uwp::TcpSocketFactory factory;
    tailgate::types::nettype::TcpSocketOptions options;
    options.ConnectAddress = "127.0.0.1";
    options.Service = "12345";
    options.NetworkInterface = "missing-test-adapter";

    EXPECT_THROW((void)factory.OpenTcpSocket(options), tailgate::uwp::NetworkAdapterUnavailable);
}

TEST_F(Given_UwpUdpSocketFactory, When_SocketRetires_Then_QueuedReadinessCannotReachItsReplacement)
{
    auto retired = Open(1);
    auto active = Open(2);
    ASSERT_TRUE(WaitBound(*retired));
    ASSERT_TRUE(WaitBound(*active));
    m_events->Post({.Token = {.Value = 1}, .Readiness = tailgate::base::EventReadiness::Error});
    m_events->Post({.Token = {.Value = 2}, .Readiness = tailgate::base::EventReadiness::Readable});

    retired->Close();
    const auto ready = m_events->TakePostedEvents(MaximumEvents);
    ASSERT_EQ(ready.size(), 1U);

    EXPECT_EQ(ready.front().Token.Value, 2U);
    EXPECT_TRUE(tailgate::base::HasReadiness(ready.front().Readiness,
                                             tailgate::base::EventReadiness::Readable));
}

} // namespace
