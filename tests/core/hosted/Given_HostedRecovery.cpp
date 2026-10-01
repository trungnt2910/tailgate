#include <gtest/gtest.h>

#include <tailgate/hosted/Recovery.h>

#include "fakes/base/FakeEventLoop.h"
#include "fakes/base/FakeTimeProvider.h"
#include "fakes/hosted/FakeTcpSocket.h"

namespace tailgate
{
namespace
{

class Given_HostedRecovery : public testing::Test
{
protected:
    Given_HostedRecovery()
    {
        Options.Socket.ConnectAddress = "192.0.2.1";
        Options.Socket.Service = "443";
        Options.Socket.NetworkInterface = "adapter-a";
        Options.Socket.NonBlockingAfterConnect = true;
        Options.HttpHost = "relay.example.com";
        Options.Client.NodePrivateKey = crypto::GeneratePrivateKey();
        Options.Client.NodePublicKey =
            crypto::X25519PublicFromPrivate(Options.Client.NodePrivateKey);
        Options.Client.DiscoPrivateKey = crypto::GeneratePrivateKey();
        Options.Client.Network.Domain("example.ts.net");
        Options.Client.Network.SelfNodeId(42);
        Options.Hostname = "client";
        Options.OperatingSystem = "TestOS";
        Options.OperatingSystemVersion = "1.0";
        Subject.Configure(Options);
    }

    tests::fakes::FakeTimeProvider Time;
    tests::fakes::FakeEventLoop Events;
    tests::fakes::hosted::FakeTcpSocketFactory Sockets{
        crypto::GeneratePrivateKey(), crypto::GeneratePrivateKey(), false};
    hosted::ConnectionOptions Options;
    hosted::Recovery Subject{Sockets, Events, Time};
};

TEST_F(Given_HostedRecovery, When_RelayFails_Then_BackoffUsesInjectedClock)
{
    const auto now = Time.Now();

    Subject.Failed();
    const auto result = Subject.Poll();

    EXPECT_EQ(Subject.Deadline(), now + std::chrono::seconds(1));
    EXPECT_FALSE(result);
    EXPECT_FALSE(Sockets.Options);
}

TEST_F(Given_HostedRecovery,
       When_RetryAuthenticates_Then_OwnerReceivesCandidateWithoutProtocolMutation)
{
    Subject.Failed();
    Time.Advance(std::chrono::seconds(1));

    const auto immediate = Subject.Poll();
    Events.WaitForWake();
    const auto connected = Subject.Poll();
    ASSERT_TRUE(connected);

    EXPECT_FALSE(immediate);
    EXPECT_EQ(connected->Configuration.NodePublicKey, Options.Client.NodePublicKey);
    EXPECT_FALSE(Subject.Deadline());
    EXPECT_EQ(Sockets.Options->NetworkInterface, "adapter-a");
}

TEST_F(Given_HostedRecovery, When_CompletedCandidateIsCancelled_Then_LateCompletionCannotAttach)
{
    Subject.Failed();
    Time.Advance(std::chrono::seconds(1));
    (void)Subject.Poll();
    Events.WaitForWake();

    Subject.Cancel();
    const auto connected = Subject.Poll();

    EXPECT_FALSE(connected);
    EXPECT_FALSE(Subject.Deadline());
}

TEST_F(Given_HostedRecovery, When_NetworkChanges_Then_RetryUsesNewAdapterWithoutWaitingForBackoff)
{
    Subject.Failed();

    Subject.ChangeNetwork("adapter-b");
    (void)Subject.Poll();
    Events.WaitForWake(2);
    const auto connected = Subject.Poll();
    ASSERT_TRUE(connected);

    EXPECT_EQ(Sockets.Options->NetworkInterface, "adapter-b");
    EXPECT_FALSE(Subject.Deadline());
}

TEST_F(Given_HostedRecovery, When_AuthenticationIsRejected_Then_SchedulesAnotherBoundedRetry)
{
    Sockets.Reject = true;
    Subject.Failed();
    Time.Advance(std::chrono::seconds(1));

    (void)Subject.Poll();
    Events.WaitForWake();
    const auto connected = Subject.Poll();

    EXPECT_FALSE(connected);
    EXPECT_EQ(Subject.Deadline(), Time.Now() + std::chrono::seconds(2));
}

TEST_F(Given_HostedRecovery, When_ResetAfterBootstrap_Then_DiscardsCandidateAndRetrySettings)
{
    Subject.Failed();
    Time.Advance(std::chrono::seconds(1));
    (void)Subject.Poll();
    Events.WaitForWake();

    Subject.Reset();
    Subject.Failed();
    Subject.ChangeNetwork("adapter-b");
    const auto connected = Subject.Poll();

    EXPECT_FALSE(connected);
    EXPECT_FALSE(Subject.Deadline());
}

TEST_F(Given_HostedRecovery, When_ConfiguredAfterReset_Then_BootstrapsNewSession)
{
    Subject.Failed();
    Time.Advance(std::chrono::seconds(1));
    (void)Subject.Poll();
    Events.WaitForWake();
    auto replacement = Options;
    replacement.Client.NodePrivateKey = crypto::GeneratePrivateKey();
    replacement.Client.NodePublicKey =
        crypto::X25519PublicFromPrivate(replacement.Client.NodePrivateKey);

    Subject.Reset();
    Subject.Configure(replacement);
    Subject.Failed();
    Time.Advance(std::chrono::seconds(1));
    (void)Subject.Poll();
    Events.WaitForWake(2);
    const auto connected = Subject.Poll();
    ASSERT_TRUE(connected);

    EXPECT_EQ(connected->Configuration.NodePublicKey, replacement.Client.NodePublicKey);
    EXPECT_FALSE(Subject.Deadline());
}

} // namespace

} // namespace tailgate
