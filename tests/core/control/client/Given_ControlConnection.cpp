#include <memory>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/control/base/ControlHandshake.h>
#include <tailgate/control/client/Connection.h>
#include <tailgate/control/client/HostInfoProvider.h>
#include <tailgate/di/Bindings.h>
#include <tailgate/types/nettype/TcpSocket.h>

#include "fakes/control/client/FakeHostInfoProvider.h"
#include "fakes/di/FakeNetworkBindings.h"
#include "fakes/types/nettype/FakeTcpSocket.h"

namespace
{

tailgate::control::client::SessionOptions Options()
{
    return tailgate::control::client::SessionOptions{
        .Host = {},
        .MachinePrivateKey = {},
        .NodePrivateKey = {},
        .ExternalNodePublicKey = std::nullopt,
        .NetworkInterface = "example0",
        .ReadinessToken = tailgate::base::EventToken{.Value = 500},
    };
}

} // namespace

TEST(Given_ControlConnection, When_BothControlTransportsFail_Then_TlsFailurePropagates)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto* socketFactory = &dynamic_cast<tailgate::tests::fakes::FakeTcpSocketFactory&>(
        injector.create<tailgate::types::nettype::TcpSocketFactory&>());
    std::vector<tailgate::types::nettype::TcpSocketOptions> attempts;
    socketFactory->Open = [&](const tailgate::types::nettype::TcpSocketOptions& options)
        -> std::unique_ptr<tailgate::types::nettype::TcpSocket>
    {
        attempts.push_back(options);
        throw std::system_error(std::make_error_code(std::errc::connection_refused));
    };
    tailgate::control::client::ConnectionFactory& factory =
        injector.create<tailgate::control::client::ConnectionFactory&>();
    const auto connect = [&]()
    {
        (void)factory.CreateConnection(Options());
    };

    EXPECT_THROW(connect(), std::system_error);
    ASSERT_EQ(attempts.size(), 2U);
    EXPECT_EQ(attempts[0].Service, tailgate::control::base::ControlHandshake::PlaintextService);
    EXPECT_FALSE(attempts[0].TlsServerName.has_value());
    EXPECT_EQ(attempts[0].NetworkInterface, std::optional<std::string>("example0"));
    EXPECT_EQ(attempts[1].Service, tailgate::control::base::ControlHandshake::TlsService);
    EXPECT_EQ(attempts[1].TlsServerName,
              std::optional<std::string>(tailgate::control::base::ControlHandshake::DefaultHost));
}

TEST(Given_ControlConnection, When_ConnectionIsCreated_Then_CoreRequestsPlatformHostInfo)
{
    tailgate::di::Injector injector;
    tailgate::tests::fakes::InstallFakeNetworkBindings(injector);
    auto& hostInfoProvider = dynamic_cast<tailgate::tests::fakes::FakeHostInfoProvider&>(
        injector.create<tailgate::control::client::HostInfoProvider&>());
    auto& socketFactory = dynamic_cast<tailgate::tests::fakes::FakeTcpSocketFactory&>(
        injector.create<tailgate::types::nettype::TcpSocketFactory&>());
    socketFactory.Open = [](const tailgate::types::nettype::TcpSocketOptions&)
        -> std::unique_ptr<tailgate::types::nettype::TcpSocket>
    {
        throw std::system_error(std::make_error_code(std::errc::connection_refused));
    };
    tailgate::control::client::ConnectionFactory& factory =
        injector.create<tailgate::control::client::ConnectionFactory&>();
    const auto connect = [&]()
    {
        (void)factory.CreateConnection(Options());
    };

    EXPECT_THROW(connect(), std::system_error);
    EXPECT_EQ(hostInfoProvider.Calls, 1U);
}
