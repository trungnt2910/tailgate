#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/base/TimeProvider.h>
#include <tailgate/derp/Connection.h>
#include <tailgate/di/Bindings.h>
#include <tailgate/types/nettype/TcpSocket.h>

#include "fakes/derp/FakeAuthenticator.h"
#include "fakes/di/FakeNetworkBindings.h"
#include "fakes/types/nettype/FakeTcpSocket.h"

namespace
{

constexpr tailgate::base::EventToken DerpToken{.Value = 400};
constexpr std::uint8_t ServerKeyFrame = 0x01;
constexpr std::uint8_t ServerInfoFrame = 0x03;
constexpr std::uint8_t ReceivePacketFrame = 0x05;
constexpr std::size_t CryptoBoxNonceSize = 24;
constexpr std::size_t CryptoBoxMacSize = 16;
constexpr std::array<std::uint8_t, 8> DerpMagic{'D', 'E', 'R', 'P', 0xf0, 0x9f, 0x94, 0x91};

std::vector<std::uint8_t> Frame(std::uint8_t type, const std::vector<std::uint8_t>& payload)
{
    const std::uint32_t size = static_cast<std::uint32_t>(payload.size());
    std::vector<std::uint8_t> result{
        type,
        static_cast<std::uint8_t>(size >> 24U),
        static_cast<std::uint8_t>(size >> 16U),
        static_cast<std::uint8_t>(size >> 8U),
        static_cast<std::uint8_t>(size),
    };
    result.insert(result.end(), payload.begin(), payload.end());
    return result;
}

std::vector<std::uint8_t> HandshakeInput()
{
    std::vector<std::uint8_t> input{'H', 'T', 'T', 'P', '/',  '1',  '.',  '1', ' ',
                                    '1', '0', '1', ' ', 'S',  'w',  'i',  't', 'c',
                                    'h', 'i', 'n', 'g', '\r', '\n', '\r', '\n'};
    tailgate::derp::DerpClient::Key serverKey{};
    serverKey.front() = 42;
    std::vector<std::uint8_t> greeting(DerpMagic.begin(), DerpMagic.end());
    greeting.insert(greeting.end(), serverKey.begin(), serverKey.end());
    const std::vector<std::uint8_t> greetingFrame = Frame(ServerKeyFrame, greeting);
    const std::vector<std::uint8_t> serverInfo =
        Frame(ServerInfoFrame, std::vector<std::uint8_t>(CryptoBoxNonceSize + CryptoBoxMacSize));
    input.insert(input.end(), greetingFrame.begin(), greetingFrame.end());
    input.insert(input.end(), serverInfo.begin(), serverInfo.end());
    return input;
}

tailgate::derp::ConnectionOptions Options()
{
    return tailgate::derp::ConnectionOptions{
        .Host = "derp.example.com",
        .NetworkInterface = "example0",
        .PrivateKey = {},
        .PublicKey = {},
        .Authenticator = {},
        .ReadinessToken = DerpToken,
        .Preferred = true,
    };
}

void FinishAttempt(tailgate::di::Injector& injector,
                   tailgate::derp::Connection& connection,
                   std::size_t wakeCount = 1)
{
    auto& events = dynamic_cast<tailgate::tests::fakes::FakeEventLoop&>(
        injector.create<tailgate::base::EventLoop&>());
    events.WaitForWake(wakeCount);
    connection.Maintain();
}

} // namespace

TEST(Given_DerpConnection, When_HandshakeSucceeds_Then_InjectedSocketBecomesNonBlocking)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto* socketFactory = &dynamic_cast<tailgate::tests::fakes::FakeTcpSocketFactory&>(
        injector.create<tailgate::types::nettype::TcpSocketFactory&>());
    auto socketState = std::make_shared<tailgate::tests::fakes::FakeTcpSocketState>();
    socketState->Incoming.push_back(HandshakeInput());
    std::optional<tailgate::types::nettype::TcpSocketOptions> socketOptions;
    socketFactory->Open = [&](const tailgate::types::nettype::TcpSocketOptions& options)
    {
        socketOptions = options;
        return std::make_unique<tailgate::tests::fakes::FakeTcpSocket>(socketState);
    };
    tailgate::derp::ConnectionOptions options = Options();
    options.Authenticator = std::make_shared<tailgate::tests::fakes::derp::FakeAuthenticator>();
    tailgate::derp::ConnectionFactory& factory =
        injector.create<tailgate::derp::ConnectionFactory&>();

    std::unique_ptr<tailgate::derp::Connection> connection =
        factory.CreateConnection(std::move(options));
    FinishAttempt(injector, *connection);

    ASSERT_TRUE(socketOptions.has_value());
    EXPECT_TRUE(connection->Connected());
    EXPECT_EQ(socketOptions->ReadinessToken, DerpToken);
    EXPECT_EQ(socketOptions->TlsServerName, std::optional<std::string>("derp.example.com"));
    EXPECT_TRUE(socketState->NonBlocking);
}

TEST(Given_DerpConnection, When_TransportIsReadable_Then_DerpPacketIsReturned)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto* socketFactory = &dynamic_cast<tailgate::tests::fakes::FakeTcpSocketFactory&>(
        injector.create<tailgate::types::nettype::TcpSocketFactory&>());
    auto socketState = std::make_shared<tailgate::tests::fakes::FakeTcpSocketState>();
    socketState->Incoming.push_back(HandshakeInput());
    socketFactory->Open = [&](const tailgate::types::nettype::TcpSocketOptions&)
    {
        return std::make_unique<tailgate::tests::fakes::FakeTcpSocket>(socketState);
    };
    tailgate::derp::ConnectionOptions options = Options();
    options.Authenticator = std::make_shared<tailgate::tests::fakes::derp::FakeAuthenticator>();
    tailgate::derp::ConnectionFactory& factory =
        injector.create<tailgate::derp::ConnectionFactory&>();
    std::unique_ptr<tailgate::derp::Connection> connection =
        factory.CreateConnection(std::move(options));
    FinishAttempt(injector, *connection);
    ASSERT_TRUE(connection->Connected());
    tailgate::derp::DerpClient::Key source{};
    source.front() = 7;
    const std::vector<std::uint8_t> packet{1, 2, 3};
    std::vector<std::uint8_t> payload(source.begin(), source.end());
    payload.insert(payload.end(), packet.begin(), packet.end());
    socketState->Incoming.push_back(Frame(ReceivePacketFrame, payload));

    const tailgate::derp::ConnectionEventResult result =
        connection->ProcessEvent(tailgate::base::Event{
            .Token = DerpToken,
            .Readiness = tailgate::base::EventReadiness::Readable,
        });

    ASSERT_EQ(result.Packets.size(), 1U);
    EXPECT_TRUE(result.Handled);
    EXPECT_EQ(result.Status, tailgate::derp::ConnectionEventStatus::Ready);
    EXPECT_EQ(result.Packets.front().Source, source);
    EXPECT_EQ(result.Packets.front().Payload, packet);
}

TEST(Given_DerpConnection, When_InitialConnectFails_Then_MaintainRetriesAfterBackoff)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto* timeProvider = &dynamic_cast<tailgate::tests::fakes::FakeTimeProvider&>(
        injector.create<tailgate::base::TimeProvider&>());
    auto* socketFactory = &dynamic_cast<tailgate::tests::fakes::FakeTcpSocketFactory&>(
        injector.create<tailgate::types::nettype::TcpSocketFactory&>());
    std::size_t attempts = 0;
    socketFactory->Open = [&](const tailgate::types::nettype::TcpSocketOptions&)
        -> std::unique_ptr<tailgate::types::nettype::TcpSocket>
    {
        ++attempts;
        throw std::system_error(std::make_error_code(std::errc::connection_refused));
    };
    tailgate::derp::ConnectionFactory& factory =
        injector.create<tailgate::derp::ConnectionFactory&>();
    std::unique_ptr<tailgate::derp::Connection> connection = factory.CreateConnection(Options());
    FinishAttempt(injector, *connection);
    ASSERT_EQ(attempts, 1U);

    timeProvider->Advance(std::chrono::milliseconds(999));
    connection->Maintain();
    const std::size_t attemptsBeforeDeadline = attempts;
    timeProvider->Advance(std::chrono::milliseconds(1));
    connection->Maintain();
    FinishAttempt(injector, *connection, 2);
    const std::size_t attemptsAtDeadline = attempts;

    EXPECT_EQ(attemptsBeforeDeadline, 1U);
    EXPECT_EQ(attemptsAtDeadline, 2U);
    EXPECT_FALSE(connection->Connected());
}

TEST(Given_DerpConnection, When_UnrelatedEventArrives_Then_ItIsNotHandled)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto* socketFactory = &dynamic_cast<tailgate::tests::fakes::FakeTcpSocketFactory&>(
        injector.create<tailgate::types::nettype::TcpSocketFactory&>());
    socketFactory->Open = [](const tailgate::types::nettype::TcpSocketOptions&)
        -> std::unique_ptr<tailgate::types::nettype::TcpSocket>
    {
        throw std::system_error(std::make_error_code(std::errc::connection_refused));
    };
    tailgate::derp::ConnectionFactory& factory =
        injector.create<tailgate::derp::ConnectionFactory&>();
    std::unique_ptr<tailgate::derp::Connection> connection = factory.CreateConnection(Options());
    FinishAttempt(injector, *connection);

    const tailgate::derp::ConnectionEventResult result =
        connection->ProcessEvent(tailgate::base::Event{
            .Token = tailgate::base::EventToken{.Value = DerpToken.Value + 1},
            .Readiness = tailgate::base::EventReadiness::Readable,
        });

    EXPECT_FALSE(result.Handled);
    EXPECT_TRUE(result.Packets.empty());
}

TEST(Given_DerpConnection, When_DialIsPending_Then_SendAndMaintainDoNotWaitOrStartAnotherDial)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto& sockets = dynamic_cast<tailgate::tests::fakes::FakeTcpSocketFactory&>(
        injector.create<tailgate::types::nettype::TcpSocketFactory&>());
    std::mutex mutex;
    std::condition_variable_any changed;
    bool entered = false;
    std::size_t attempts = 0;
    sockets.Open = [&](const tailgate::types::nettype::TcpSocketOptions& options)
        -> std::unique_ptr<tailgate::types::nettype::TcpSocket>
    {
        std::unique_lock lock(mutex);
        ++attempts;
        entered = true;
        changed.notify_all();
        changed.wait(lock,
                     options.Cancellation,
                     []
                     {
                         return false;
                     });
        throw std::system_error(std::make_error_code(std::errc::operation_canceled));
    };
    auto connection =
        injector.create<tailgate::derp::ConnectionFactory&>().CreateConnection(Options());
    std::unique_lock lock(mutex);
    changed.wait(lock,
                 [&]
                 {
                     return entered;
                 });
    lock.unlock();

    connection->Send({}, {1, 2, 3});
    connection->Maintain();
    const bool connected = connection->Connected();
    connection.reset();

    EXPECT_FALSE(connected);
    EXPECT_EQ(attempts, 1U);
}

TEST(Given_DerpConnection, When_CancelledDuringAuthentication_Then_WorkerStopsBeforeDependenciesDie)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto& sockets = dynamic_cast<tailgate::tests::fakes::FakeTcpSocketFactory&>(
        injector.create<tailgate::types::nettype::TcpSocketFactory&>());
    auto state = std::make_shared<tailgate::tests::fakes::FakeTcpSocketState>();
    state->Incoming.push_back(HandshakeInput());
    sockets.Open = [&](const auto&)
    {
        return std::make_unique<tailgate::tests::fakes::FakeTcpSocket>(state);
    };
    auto authenticator = std::make_shared<tailgate::tests::fakes::derp::FakeAuthenticator>();
    std::mutex mutex;
    std::condition_variable_any changed;
    bool entered = false;
    bool cancelled = false;
    authenticator->OnAuthenticate = [&](const auto&,
                                        std::stop_token cancellation) -> std::vector<std::uint8_t>
    {
        std::unique_lock lock(mutex);
        entered = true;
        changed.notify_all();
        changed.wait(lock,
                     cancellation,
                     []
                     {
                         return false;
                     });
        cancelled = cancellation.stop_requested();
        throw std::system_error(std::make_error_code(std::errc::operation_canceled));
    };
    auto options = Options();
    options.Authenticator = authenticator;
    auto connection =
        injector.create<tailgate::derp::ConnectionFactory&>().CreateConnection(options);
    std::unique_lock lock(mutex);
    changed.wait(lock,
                 [&]
                 {
                     return entered;
                 });
    lock.unlock();

    connection.reset();

    EXPECT_TRUE(cancelled);
    EXPECT_TRUE(state->Destroyed);
}

TEST(Given_DerpConnection, When_PacketsArriveBeforeHandshakeCompletes_Then_TheyFlushAfterAdoption)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto& sockets = dynamic_cast<tailgate::tests::fakes::FakeTcpSocketFactory&>(
        injector.create<tailgate::types::nettype::TcpSocketFactory&>());
    auto state = std::make_shared<tailgate::tests::fakes::FakeTcpSocketState>();
    state->Incoming.push_back(HandshakeInput());
    std::mutex mutex;
    std::condition_variable_any changed;
    bool release = false;
    sockets.Open = [&](const auto& options) -> std::unique_ptr<tailgate::types::nettype::TcpSocket>
    {
        std::unique_lock lock(mutex);
        changed.wait(lock,
                     options.Cancellation,
                     [&]
                     {
                         return release;
                     });
        return std::make_unique<tailgate::tests::fakes::FakeTcpSocket>(state);
    };
    auto options = Options();
    options.Authenticator = std::make_shared<tailgate::tests::fakes::derp::FakeAuthenticator>();
    auto connection =
        injector.create<tailgate::derp::ConnectionFactory&>().CreateConnection(options);
    const std::vector<std::uint8_t> packet{71, 72, 73};

    connection->Send({}, packet);
    {
        std::lock_guard lock(mutex);
        release = true;
    }
    changed.notify_all();
    auto& events = dynamic_cast<tailgate::tests::fakes::FakeEventLoop&>(
        injector.create<tailgate::base::EventLoop&>());
    events.WaitForWake();
    const auto ready = events.TakePostedEvents(1);
    ASSERT_EQ(ready.size(), 1U);
    (void)connection->ProcessEvent(ready.front());

    EXPECT_TRUE(connection->Connected());
    EXPECT_NE(
        std::search(state->Written.begin(), state->Written.end(), packet.begin(), packet.end()),
        state->Written.end());
}

TEST(Given_DerpConnection, When_TransportCloses_Then_BackoffReconnectFlushesQueuedPackets)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto& time = dynamic_cast<tailgate::tests::fakes::FakeTimeProvider&>(
        injector.create<tailgate::base::TimeProvider&>());
    auto& sockets = dynamic_cast<tailgate::tests::fakes::FakeTcpSocketFactory&>(
        injector.create<tailgate::types::nettype::TcpSocketFactory&>());
    std::vector<std::shared_ptr<tailgate::tests::fakes::FakeTcpSocketState>> states;
    sockets.Open = [&](const auto&)
    {
        auto state = std::make_shared<tailgate::tests::fakes::FakeTcpSocketState>();
        state->Incoming.push_back(HandshakeInput());
        states.push_back(state);
        return std::make_unique<tailgate::tests::fakes::FakeTcpSocket>(state);
    };
    auto options = Options();
    options.Authenticator = std::make_shared<tailgate::tests::fakes::derp::FakeAuthenticator>();
    auto connection =
        injector.create<tailgate::derp::ConnectionFactory&>().CreateConnection(options);
    FinishAttempt(injector, *connection);
    const std::vector<std::uint8_t> packet{71, 72, 73};

    const auto closed = connection->ProcessEvent(
        {.Token = DerpToken, .Readiness = tailgate::base::EventReadiness::Closed});
    connection->Send({}, packet);
    const auto beforeDeadline = states.size();
    time.Advance(std::chrono::seconds(1));
    connection->Maintain();
    FinishAttempt(injector, *connection, 2);
    ASSERT_EQ(states.size(), 2U);

    EXPECT_EQ(closed.Status, tailgate::derp::ConnectionEventStatus::Disconnected);
    EXPECT_EQ(beforeDeadline, 1U);
    EXPECT_TRUE(states.front()->Destroyed);
    EXPECT_TRUE(connection->Connected());
    EXPECT_NE(std::search(states.back()->Written.begin(),
                          states.back()->Written.end(),
                          packet.begin(),
                          packet.end()),
              states.back()->Written.end());
}

TEST(Given_DerpConnection, When_ReceiveBatchLeavesBufferedFrames_Then_AnotherEventDrainsThem)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto& sockets = dynamic_cast<tailgate::tests::fakes::FakeTcpSocketFactory&>(
        injector.create<tailgate::types::nettype::TcpSocketFactory&>());
    auto state = std::make_shared<tailgate::tests::fakes::FakeTcpSocketState>();
    state->Incoming.push_back(HandshakeInput());
    sockets.Open = [&](const auto&)
    {
        return std::make_unique<tailgate::tests::fakes::FakeTcpSocket>(state);
    };
    auto options = Options();
    options.Authenticator = std::make_shared<tailgate::tests::fakes::derp::FakeAuthenticator>();
    auto connection =
        injector.create<tailgate::derp::ConnectionFactory&>().CreateConnection(options);
    FinishAttempt(injector, *connection);
    auto& events = dynamic_cast<tailgate::tests::fakes::FakeEventLoop&>(
        injector.create<tailgate::base::EventLoop&>());
    (void)events.TakePostedEvents(1);
    constexpr std::size_t PacketCount = 257;
    const auto frame =
        Frame(ReceivePacketFrame,
              std::vector<std::uint8_t>(tailgate::derp::DerpClient::Key{}.size() + 1));
    std::vector<std::uint8_t> input;
    for (std::size_t index = 0; index < PacketCount; ++index)
    {
        input.insert(input.end(), frame.begin(), frame.end());
    }
    state->Incoming.push_back(std::move(input));

    const auto first = connection->ProcessEvent(
        {.Token = DerpToken, .Readiness = tailgate::base::EventReadiness::Readable});
    const auto ready = events.TakePostedEvents(1);
    ASSERT_EQ(ready.size(), 1U);
    const auto second = connection->ProcessEvent(ready.front());

    EXPECT_FALSE(first.Packets.empty());
    EXPECT_FALSE(second.Packets.empty());
    EXPECT_EQ(first.Packets.size() + second.Packets.size(), PacketCount);
}

TEST(Given_DerpConnection, When_DelegationIsReleased_Then_ClosesSocketAndSuppressesReconnect)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto& sockets = dynamic_cast<tailgate::tests::fakes::FakeTcpSocketFactory&>(
        injector.create<tailgate::types::nettype::TcpSocketFactory&>());
    auto state = std::make_shared<tailgate::tests::fakes::FakeTcpSocketState>();
    state->Incoming.push_back(HandshakeInput());
    std::size_t opens = 0;
    sockets.Open = [&](const auto&)
    {
        ++opens;
        return std::make_unique<tailgate::tests::fakes::FakeTcpSocket>(state);
    };
    auto options = Options();
    options.Authenticator = std::make_shared<tailgate::tests::fakes::derp::FakeAuthenticator>();
    auto connection =
        injector.create<tailgate::derp::ConnectionFactory&>().CreateConnection(options);
    FinishAttempt(injector, *connection);
    ASSERT_TRUE(connection->Connected());

    connection->SetEnabled(false);
    dynamic_cast<tailgate::tests::fakes::FakeTimeProvider&>(
        injector.create<tailgate::base::TimeProvider&>())
        .Advance(std::chrono::minutes(1));
    connection->Send({}, {1, 2, 3});
    connection->Maintain();

    EXPECT_TRUE(state->Closed);
    EXPECT_FALSE(connection->Connected());
    EXPECT_EQ(opens, 1U);
}

TEST(Given_DerpConnection, When_AdapterChanges_Then_ReauthenticatesOnReplacementTransport)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto& sockets = dynamic_cast<tailgate::tests::fakes::FakeTcpSocketFactory&>(
        injector.create<tailgate::types::nettype::TcpSocketFactory&>());
    std::vector<tailgate::types::nettype::TcpSocketOptions> opened;
    std::vector<std::shared_ptr<tailgate::tests::fakes::FakeTcpSocketState>> states;
    sockets.Open = [&](const auto& options)
    {
        opened.push_back(options);
        auto state = std::make_shared<tailgate::tests::fakes::FakeTcpSocketState>();
        state->Incoming.push_back(HandshakeInput());
        states.push_back(state);
        return std::make_unique<tailgate::tests::fakes::FakeTcpSocket>(state);
    };
    auto options = Options();
    options.Authenticator = std::make_shared<tailgate::tests::fakes::derp::FakeAuthenticator>();
    auto connection =
        injector.create<tailgate::derp::ConnectionFactory&>().CreateConnection(options);
    FinishAttempt(injector, *connection);

    connection->ChangeNetwork("replacement0");
    FinishAttempt(injector, *connection, 2);
    ASSERT_EQ(opened.size(), 2U);

    EXPECT_TRUE(states.front()->Closed);
    EXPECT_TRUE(connection->Connected());
    EXPECT_EQ(opened.back().NetworkInterface, "replacement0");
}
