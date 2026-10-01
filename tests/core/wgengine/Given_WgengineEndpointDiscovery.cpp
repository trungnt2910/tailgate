#include <algorithm>
#include <chrono>
#include <memory>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/wgengine/Session.h>
#include <tailgate/wgengine/magicsock/Connection.h>

#include "fakes/derp/FakeConnection.h"
#include "fakes/di/FakeNetworkBindings.h"

namespace tailgate
{
namespace
{

using namespace std::chrono_literals;
constexpr base::EventToken UdpToken{.Value = 602};
constexpr base::EventToken DerpToken{.Value = 601};

class Given_WgengineEndpointDiscovery : public testing::Test
{
protected:
    void SetUp() override
    {
        tests::fakes::InstallFakeNetworkBindings(Injector);
        auto& udp = Injector.create<wgengine::magicsock::Connection&>();
        ASSERT_TRUE(udp.Open(
            {.BindEndpoint = {}, .NetworkInterface = std::nullopt, .ReadinessToken = UdpToken}));
        Events().Next.Status = base::EventWaitStatus::Woken;
    }

    wgengine::Session& Session()
    {
        return Injector.create<wgengine::Session&>();
    }

    tests::fakes::FakeEventLoop& Events()
    {
        return dynamic_cast<tests::fakes::FakeEventLoop&>(Injector.create<base::EventLoop&>());
    }

    tests::fakes::FakeTimeProvider& Time()
    {
        return dynamic_cast<tests::fakes::FakeTimeProvider&>(
            Injector.create<base::TimeProvider&>());
    }

    tests::fakes::FakeUdpSocketState& Socket()
    {
        return *dynamic_cast<tests::fakes::FakeUdpSocketFactory&>(
                    Injector.create<types::nettype::UdpSocketFactory&>())
                    .States.front();
    }

    wgengine::SessionWaitResult Wait()
    {
        return Session().Wait(8, 16, 4096);
    }

    void Respond(const std::vector<std::uint8_t>& request, const net::Endpoint& source)
    {
        // XOR-MAPPED-ADDRESS for 192.0.2.10:41641, with the request's transaction ID.
        std::vector<std::uint8_t> response{0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xa4, 0x42,
                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                           0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x08,
                                           0x00, 0x01, 0x83, 0xbb, 0xe1, 0x12, 0xa6, 0x48};
        std::copy_n(request.begin() + 8, 12, response.begin() + 8);
        Socket().Incoming.push_back(
            {.Result = types::nettype::SocketIoResult::Complete,
             .Datagram = {.Source = source, .Payload = std::move(response)}});
        Events().Post({.Token = UdpToken, .Readiness = base::EventReadiness::Readable});
    }

    di::Injector Injector;
    const net::Endpoint Server = net::Endpoint::Parse("192.0.2.20:3478");
    const net::Endpoint Mapped = net::Endpoint::Parse("192.0.2.10:41641");
};

TEST_F(Given_WgengineEndpointDiscovery, When_StartingDiscovery_Then_DoesNotWaitOrReadOtherTraffic)
{
    auto& session = Session();

    session.StartEndpointDiscovery(Server, 3s);

    EXPECT_EQ(Events().TimedWaitCalls, 0U);
    EXPECT_TRUE(Socket().Sent.empty());
}

TEST_F(Given_WgengineEndpointDiscovery, When_StunAndDerpArriveTogether_Then_DeliversBoth)
{
    const derp::DerpClient::Packet packet{.Source = {}, .Payload = {1, 2, 3}};
    (void)Session().AddDerpConnection(
        1, std::make_unique<tests::fakes::derp::FakeConnection>(DerpToken, packet));
    Socket().OnSend = [&](const net::Endpoint&, const std::vector<std::uint8_t>& request)
    {
        Respond(request, Server);
    };
    Session().StartEndpointDiscovery(Server, 3s);
    Events().Post({.Token = DerpToken, .Readiness = base::EventReadiness::Readable});

    const auto result = Wait();
    const auto next = Wait();
    ASSERT_TRUE(result.EndpointDiscovery);
    ASSERT_EQ(result.DerpPackets.size(), 1U);

    EXPECT_EQ(result.EndpointDiscovery->Endpoint, Mapped);
    EXPECT_EQ(result.DerpPackets.front().Packet.Payload, packet.Payload);
    EXPECT_EQ(result.Status, base::EventWaitStatus::Events);
    EXPECT_TRUE(result.Datagrams.empty());
    EXPECT_FALSE(next.EndpointDiscovery);
}

TEST_F(Given_WgengineEndpointDiscovery, When_ResponseHasWrongSource_Then_DiscoveryRemainsPending)
{
    Socket().OnSend = [&](const net::Endpoint&, const std::vector<std::uint8_t>& request)
    {
        Respond(request, net::Endpoint::Parse("192.0.2.21:3478"));
    };
    Session().StartEndpointDiscovery(Server, 3s);

    const auto result = Wait();
    Respond(Socket().Sent.front().Payload, Server);
    const auto correct = Wait();
    ASSERT_TRUE(correct.EndpointDiscovery);

    EXPECT_FALSE(result.EndpointDiscovery);
    EXPECT_EQ(result.Datagrams.size(), 1U);
    EXPECT_EQ(correct.EndpointDiscovery->Endpoint, Mapped);
}

TEST_F(Given_WgengineEndpointDiscovery,
       When_PreviousTransactionResponds_Then_OnlyNewResponseCompletes)
{
    Session().StartEndpointDiscovery(Server, 3s);
    (void)Wait();
    ASSERT_EQ(Socket().Sent.size(), 1U);
    const auto previous = Socket().Sent.front().Payload;

    Session().StartEndpointDiscovery(Server, 3s);
    Respond(previous, Server);
    const auto stale = Wait();
    Respond(Socket().Sent.back().Payload, Server);
    const auto current = Wait();
    ASSERT_TRUE(current.EndpointDiscovery);

    EXPECT_FALSE(stale.EndpointDiscovery);
    EXPECT_EQ(stale.Datagrams.size(), 1U);
    EXPECT_EQ(current.EndpointDiscovery->Endpoint, Mapped);
}

TEST_F(Given_WgengineEndpointDiscovery, When_SendIsBackpressured_Then_RetriesOnlyWhenTimerExpires)
{
    Socket().SendResult = types::nettype::SocketIoResult::WouldBlock;
    Session().StartEndpointDiscovery(Server, 3s);

    const auto blocked = Wait();
    Socket().SendResult = types::nettype::SocketIoResult::Complete;
    (void)Wait();
    const auto beforeDeadline = Socket().Sent.size();
    Time().Advance(500ms);
    (void)Wait();
    const auto firstRetry = Socket().Sent.size();
    Time().Advance(500ms);
    (void)Wait();
    const auto beforeSecondDeadline = Socket().Sent.size();
    Time().Advance(500ms);
    (void)Wait();
    ASSERT_EQ(Socket().Sent.size(), 2U);

    EXPECT_FALSE(blocked.EndpointDiscovery);
    EXPECT_EQ(beforeDeadline, 0U);
    EXPECT_EQ(firstRetry, 1U);
    EXPECT_EQ(beforeSecondDeadline, 1U);
    EXPECT_EQ(Socket().Sent.front().Payload, Socket().Sent.back().Payload);
}

TEST_F(Given_WgengineEndpointDiscovery,
       When_DeadlineExpires_Then_ReportsFailureOnceAndRejectsLateReply)
{
    Session().StartEndpointDiscovery(Server, 3s);
    (void)Wait();
    ASSERT_EQ(Socket().Sent.size(), 1U);
    Respond(Socket().Sent.front().Payload, Server);

    Time().Advance(3s);
    const auto expired = Wait();
    const auto next = Wait();
    ASSERT_TRUE(expired.EndpointDiscovery);

    EXPECT_FALSE(expired.EndpointDiscovery->Endpoint);
    EXPECT_EQ(expired.Datagrams.size(), 1U);
    EXPECT_FALSE(next.EndpointDiscovery);
    EXPECT_EQ(Socket().Sent.size(), 1U);
}

TEST_F(Given_WgengineEndpointDiscovery, When_Cancelled_Then_LateReplyAndTimersCannotCompleteIt)
{
    Session().StartEndpointDiscovery(Server, 3s);
    (void)Wait();
    ASSERT_EQ(Socket().Sent.size(), 1U);
    Respond(Socket().Sent.front().Payload, Server);

    Session().CancelEndpointDiscovery();
    Time().Advance(3s);
    const auto result = Wait();

    EXPECT_FALSE(result.EndpointDiscovery);
    EXPECT_EQ(result.Datagrams.size(), 1U);
    EXPECT_EQ(Socket().Sent.size(), 1U);
}

TEST_F(Given_WgengineEndpointDiscovery, When_UdpFailsWithReplyQueued_Then_DoesNotPublishFailedPath)
{
    Session().StartEndpointDiscovery(Server, 3s);
    (void)Wait();
    ASSERT_EQ(Socket().Sent.size(), 1U);
    Respond(Socket().Sent.front().Payload, Server);
    Events().Post({.Token = UdpToken, .Readiness = base::EventReadiness::Error});

    const auto result = Wait();
    ASSERT_TRUE(result.EndpointDiscovery);

    EXPECT_FALSE(result.EndpointDiscovery->Endpoint);
    EXPECT_EQ(result.Failures.size(), 1U);
}

TEST_F(Given_WgengineEndpointDiscovery, When_SocketIsClosed_Then_CompletesWithoutWaitingForTimeout)
{
    Socket().Closed = true;
    Session().StartEndpointDiscovery(Server, 3s);

    const auto result = Wait();
    ASSERT_TRUE(result.EndpointDiscovery);

    EXPECT_FALSE(result.EndpointDiscovery->Endpoint);
    EXPECT_TRUE(Socket().Sent.empty());
}

TEST_F(Given_WgengineEndpointDiscovery,
       When_ProbeSendThrows_Then_ReturnsFailureWithoutRetiringSession)
{
    Socket().OnSend = [](const net::Endpoint&, const std::vector<std::uint8_t>&)
    {
        throw std::system_error(std::make_error_code(std::errc::network_unreachable));
    };
    Session().StartEndpointDiscovery(Server, 3s);

    const auto result = Wait();
    ASSERT_TRUE(result.EndpointDiscovery);

    EXPECT_FALSE(result.EndpointDiscovery->Endpoint);
    EXPECT_FALSE(Socket().Closed);
}

} // namespace

} // namespace tailgate
