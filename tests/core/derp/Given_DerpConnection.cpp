#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
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
    options.Authenticator = [](const tailgate::derp::DerpClient::Key&)
    {
        return std::vector<std::uint8_t>(tailgate::derp::DerpClient::Key{}.size() +
                                         CryptoBoxNonceSize + CryptoBoxMacSize);
    };
    tailgate::derp::ConnectionFactory& factory =
        injector.create<tailgate::derp::ConnectionFactory&>();

    std::unique_ptr<tailgate::derp::Connection> connection =
        factory.CreateConnection(std::move(options));

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
    options.Authenticator = [](const tailgate::derp::DerpClient::Key&)
    {
        return std::vector<std::uint8_t>(tailgate::derp::DerpClient::Key{}.size() +
                                         CryptoBoxNonceSize + CryptoBoxMacSize);
    };
    tailgate::derp::ConnectionFactory& factory =
        injector.create<tailgate::derp::ConnectionFactory&>();
    std::unique_ptr<tailgate::derp::Connection> connection =
        factory.CreateConnection(std::move(options));
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
    ASSERT_EQ(attempts, 1U);

    timeProvider->Advance(std::chrono::milliseconds(999));
    connection->Maintain();
    const std::size_t attemptsBeforeDeadline = attempts;
    timeProvider->Advance(std::chrono::milliseconds(1));
    connection->Maintain();
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

    const tailgate::derp::ConnectionEventResult result =
        connection->ProcessEvent(tailgate::base::Event{
            .Token = tailgate::base::EventToken{.Value = DerpToken.Value + 1},
            .Readiness = tailgate::base::EventReadiness::Readable,
        });

    EXPECT_FALSE(result.Handled);
    EXPECT_TRUE(result.Packets.empty());
}
