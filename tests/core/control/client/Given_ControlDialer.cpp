#include <stdexcept>
#include <vector>

#include <gtest/gtest.h>

#include "fakes/control/client/FakeControlDialer.h"

using tailgate::tests::fakes::FakeControlDialer;
using tailgate::tests::fakes::FakeTcpSocket;

TEST(Given_ControlDialer, When_WorkingPlaintextControlAndDialing_Then_TlsIsNeverAttempted)
{
    FakeControlDialer dialer;

    tailgate::control::client::impl::ControlDialOutcome outcome = dialer.Dial();

    EXPECT_FALSE(outcome.UsedTls);
    EXPECT_FALSE(dialer.TlsDialed);
    EXPECT_EQ(dialer.Established, std::vector<std::string>{"plaintext"});
    EXPECT_EQ(dynamic_cast<FakeTcpSocket&>(*outcome.Stream).Name(), "plaintext");
}

TEST(Given_ControlDialer, When_PlaintextControlConnectFailureAndDialing_Then_TlsFallbackIsUsed)
{
    FakeControlDialer dialer;
    dialer.PlaintextOpenFails = true;

    tailgate::control::client::impl::ControlDialOutcome outcome = dialer.Dial();

    EXPECT_TRUE(outcome.UsedTls);
    EXPECT_EQ(dialer.Established, std::vector<std::string>{"tls"});
    EXPECT_EQ(dynamic_cast<FakeTcpSocket&>(*outcome.Stream).Name(), "tls");
}

TEST(Given_ControlDialer, When_PlaintextControlHandshakeFailureAndDialing_Then_TlsFallbackIsUsed)
{
    FakeControlDialer dialer;
    dialer.PlaintextEstablishFails = true;

    tailgate::control::client::impl::ControlDialOutcome outcome = dialer.Dial();

    EXPECT_TRUE(outcome.UsedTls);
    EXPECT_EQ(dialer.Established, (std::vector<std::string>{"plaintext", "tls"}));
    EXPECT_EQ(dynamic_cast<FakeTcpSocket&>(*outcome.Stream).Name(), "tls");
}

TEST(Given_ControlDialer, When_BothControlPathsFailingAndDialing_Then_TheTlsErrorPropagates)
{
    FakeControlDialer dialer;
    dialer.PlaintextOpenFails = true;
    dialer.TlsOpenFails = true;
    const auto dial = [&]()
    {
        (void)dialer.Dial();
    };

    EXPECT_THROW(dial(), std::runtime_error);
}
