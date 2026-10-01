#include <chrono>
#include <functional>
#include <memory>
#include <stdexcept>
#include <stop_token>
#include <system_error>

#include <gtest/gtest.h>

#include <tailgate/wgengine/magicsock/Bind.h>

#include "wgengine/magicsock/impl/ConnectionImpl.h"

#include "fakes/base/FakeTimeProvider.h"
#include "fakes/types/nettype/FakeUdpSocket.h"

namespace
{

using namespace std::chrono_literals;
using tailgate::base::Event;
using tailgate::base::EventReadiness;
using tailgate::base::EventWaitResult;
using tailgate::base::EventWaitStatus;
using tailgate::tests::fakes::FakeUdpSocket;
using tailgate::tests::fakes::FakeUdpSocketState;
constexpr tailgate::base::EventToken SocketToken{.Value = 10};
constexpr tailgate::base::EventToken OtherToken{.Value = 20};

class BindSocketFactory final : public tailgate::types::nettype::UdpSocketFactory
{
public:
    std::unique_ptr<tailgate::types::nettype::UdpSocket>
    OpenUdpSocket(const tailgate::types::nettype::UdpSocketOptions&) override
    {
        ++Opens;
        return std::make_unique<FakeUdpSocket>(State);
    }

    std::shared_ptr<FakeUdpSocketState> State = std::make_shared<FakeUdpSocketState>();
    int Opens = 0;
};

class BindEventLoop final : public tailgate::base::EventLoop
{
public:
    EventWaitResult Wait(std::size_t) override
    {
        throw std::logic_error("binding must use a deadline");
    }

    EventWaitResult Wait(const tailgate::base::WaitToken&, std::size_t) override
    {
        ++Waits;
        return OnWait();
    }

    void Wake() noexcept override
    {
        ++Wakes;
    }

    std::function<EventWaitResult()> OnWait;
    int Waits = 0;
    int Wakes = 0;
};

class Given_MagicsockBind : public testing::Test
{
protected:
    tailgate::net::Endpoint Bind(std::stop_token cancellation = {})
    {
        return tailgate::wgengine::magicsock::Bind(
            Connection, Options, Events, Time, 10s, cancellation);
    }

    std::error_code Failure(std::stop_token cancellation = {})
    {
        try
        {
            (void)Bind(cancellation);
            return {};
        }
        catch (const std::system_error& error)
        {
            return error.code();
        }
    }

    const tailgate::net::Endpoint Local = tailgate::net::Endpoint::Parse("192.0.2.1:12345");
    const tailgate::types::nettype::UdpSocketOptions Options{
        .BindEndpoint = {}, .NetworkInterface = std::nullopt, .ReadinessToken = SocketToken};
    BindSocketFactory Factory;
    tailgate::tests::fakes::FakeTimeProvider Time;
    BindEventLoop Events;
    tailgate::wgengine::magicsock::impl::ConnectionImpl Connection{Factory, Time};
};

TEST_F(Given_MagicsockBind, When_BindingIsSynchronous_Then_NoWaitIsNeeded)
{
    Factory.State->LocalEndpoint = Local;

    const auto endpoint = Bind();

    EXPECT_EQ(endpoint, Local);
    EXPECT_EQ(Events.Waits, 0);
    EXPECT_FALSE(Factory.State->Closed);
}

TEST_F(Given_MagicsockBind, When_BindingCompletesAsynchronously_Then_ReturnsBoundEndpoint)
{
    Events.OnWait = [&]()
    {
        Factory.State->LocalEndpoint = Local;
        Events.Post({.Token = SocketToken, .Readiness = EventReadiness::Writable});
        return EventWaitResult{.Status = EventWaitStatus::Woken, .Events = {}};
    };

    const auto endpoint = Bind();

    EXPECT_EQ(endpoint, Local);
    EXPECT_EQ(Events.Waits, 1);
    EXPECT_TRUE(Events.TakePostedEvents(8).empty());
    EXPECT_FALSE(Factory.State->Closed);
}

TEST_F(Given_MagicsockBind, When_BindingFails_Then_ClosesOnlyOpenedTransport)
{
    Events.OnWait = [&]()
    {
        Events.Post({.Token = SocketToken, .Readiness = EventReadiness::Error});
        return EventWaitResult{.Status = EventWaitStatus::Woken, .Events = {}};
    };

    const auto error = Failure();

    EXPECT_EQ(error, std::errc::network_unreachable);
    EXPECT_TRUE(Factory.State->Closed);
    EXPECT_FALSE(Connection.LocalEndpoint());
}

TEST_F(Given_MagicsockBind, When_TransportClosesDuringBind_Then_ReportsClosed)
{
    Events.OnWait = [&]()
    {
        return EventWaitResult{
            .Events = {{.Token = SocketToken, .Readiness = EventReadiness::Closed}}};
    };

    const auto error = Failure();

    EXPECT_EQ(error, std::errc::not_connected);
    EXPECT_TRUE(Factory.State->Closed);
}

TEST_F(Given_MagicsockBind, When_BindDeadlineExpires_Then_ClosesPendingTransport)
{
    Events.OnWait = []()
    {
        return EventWaitResult{.Status = EventWaitStatus::DeadlineReached, .Events = {}};
    };

    const auto error = Failure();

    EXPECT_EQ(error, std::errc::timed_out);
    EXPECT_EQ(Events.Waits, 1);
    EXPECT_TRUE(Factory.State->Closed);
}

TEST_F(Given_MagicsockBind, When_OtherWakeCoincidesWithDeadline_Then_BindStillExpires)
{
    Events.OnWait = [&]()
    {
        Time.Advance(10s);
        return EventWaitResult{.Status = EventWaitStatus::Woken, .Events = {}};
    };

    const auto error = Failure();

    EXPECT_EQ(error, std::errc::timed_out);
    EXPECT_EQ(Events.Waits, 1);
    EXPECT_TRUE(Factory.State->Closed);
}

TEST_F(Given_MagicsockBind, When_WokenBeforeBindCompletes_Then_WaitsForActualEndpoint)
{
    Events.OnWait = [&]()
    {
        if (Events.Waits == 2)
        {
            Factory.State->LocalEndpoint = Local;
        }
        return EventWaitResult{.Status = EventWaitStatus::Woken, .Events = {}};
    };

    const auto endpoint = Bind();

    EXPECT_EQ(endpoint, Local);
    EXPECT_EQ(Events.Waits, 2);
}

TEST_F(Given_MagicsockBind, When_CancelledBeforeOpen_Then_DoesNotCreateSocket)
{
    std::stop_source cancellation;
    cancellation.request_stop();

    const auto error = Failure(cancellation.get_token());

    EXPECT_EQ(error, std::errc::operation_canceled);
    EXPECT_EQ(Factory.Opens, 0);
    EXPECT_EQ(Events.Waits, 0);
}

TEST_F(Given_MagicsockBind, When_CancelledWhileWaiting_Then_WakesAndClosesPendingTransport)
{
    std::stop_source cancellation;
    Events.OnWait = [&]()
    {
        cancellation.request_stop();
        return EventWaitResult{.Status = EventWaitStatus::Woken, .Events = {}};
    };

    const auto error = Failure(cancellation.get_token());

    EXPECT_EQ(error, std::errc::operation_canceled);
    EXPECT_EQ(Events.Wakes, 1);
    EXPECT_EQ(Events.Waits, 1);
    EXPECT_TRUE(Factory.State->Closed);
}

TEST_F(Given_MagicsockBind, When_ConnectionAlreadyOpen_Then_DoesNotCloseExistingSocket)
{
    Factory.State->LocalEndpoint = Local;
    ASSERT_TRUE(Connection.Open(Options));

    const auto error = Failure();

    EXPECT_EQ(error, std::errc::address_not_available);
    EXPECT_EQ(Factory.Opens, 1);
    EXPECT_EQ(Connection.LocalEndpoint(), Local);
    EXPECT_FALSE(Factory.State->Closed);
}

TEST_F(Given_MagicsockBind, When_OtherReadinessArrivesDuringBind_Then_PreservesItForDispatcher)
{
    Events.OnWait = [&]()
    {
        Factory.State->LocalEndpoint = Local;
        Events.Post({.Token = OtherToken, .Readiness = EventReadiness::Readable});
        return EventWaitResult{
            .Events = {{.Token = OtherToken, .Readiness = EventReadiness::Writable}}};
    };

    const auto endpoint = Bind();
    const auto deferred = Events.TakePostedEvents(8);
    ASSERT_EQ(deferred.size(), 1U);

    EXPECT_EQ(endpoint, Local);
    EXPECT_EQ(deferred.front().Token, OtherToken);
    EXPECT_EQ(deferred.front().Readiness, EventReadiness::Readable | EventReadiness::Writable);
}

TEST_F(Given_MagicsockBind, When_BindFailsAlongsideOtherReadiness_Then_PreservesOtherReadiness)
{
    Events.OnWait = [&]()
    {
        return EventWaitResult{
            .Events = {{.Token = SocketToken, .Readiness = EventReadiness::Error},
                       {.Token = OtherToken, .Readiness = EventReadiness::Readable}}};
    };

    const auto error = Failure();
    const auto deferred = Events.TakePostedEvents(8);
    ASSERT_EQ(deferred.size(), 1U);

    EXPECT_EQ(error, std::errc::network_unreachable);
    EXPECT_EQ(deferred.front().Token, OtherToken);
    EXPECT_EQ(deferred.front().Readiness, EventReadiness::Readable);
}

TEST_F(Given_MagicsockBind, When_ReceiveRacesBinding_Then_PreservesDatagramReadiness)
{
    Events.OnWait = [&]()
    {
        Factory.State->LocalEndpoint = Local;
        return EventWaitResult{
            .Events = {{.Token = SocketToken,
                        .Readiness = EventReadiness::Readable | EventReadiness::Writable}}};
    };

    const auto endpoint = Bind();
    const auto deferred = Events.TakePostedEvents(8);
    ASSERT_EQ(deferred.size(), 1U);

    EXPECT_EQ(endpoint, Local);
    EXPECT_EQ(deferred.front().Token, SocketToken);
    EXPECT_EQ(deferred.front().Readiness, EventReadiness::Readable);
}

} // namespace
