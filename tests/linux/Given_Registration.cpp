#include <chrono>
#include <optional>
#include <string>

#include <gtest/gtest.h>

#include <tailgate/control/client/ControlClient.h>

#include "Lifecycle.h"
#include "Registration.h"
#include "State.h"

#include "LinuxTestEnvironment.h"

TEST(Given_Registration, When_LoginIsRequired_Then_LoginStateIsPersisted)
{
    tailgate::test::LinuxTestHome home("linux-registration-login");
    std::string pendingAuthKey = "tskey-auth-fake";
    std::string fallbackAuthKey = "tskey-auth-fallback-fake";
    std::string pendingAuthorizationUrl;
    tailgate::linux_frontend::DaemonStatus status;
    tailgate::linux_frontend::Registration subject(
        pendingAuthKey, fallbackAuthKey, pendingAuthorizationUrl, status);
    const tailgate::control::client::RegistrationResult registration{
        .State = tailgate::control::client::RegistrationState::LoginRequired,
        .AuthorizationUrl = "https://login.tailscale.com/a/fake-login-code",
        .AuthorizationCode = "fake-login-code",
        .ApprovalUrl = {},
        .Network = std::nullopt,
        .NetworkMapStreaming = false,
    };

    subject.StateChanged(registration);
    const auto persisted = tailgate::linux_frontend::ReadDaemonStatus();

    ASSERT_TRUE(persisted.has_value());
    EXPECT_EQ(pendingAuthorizationUrl, registration.AuthorizationUrl);
    EXPECT_EQ(status.BackendState, "NeedsLogin");
    EXPECT_FALSE(status.Online);
    EXPECT_EQ(status.AuthorizationUrl, registration.AuthorizationUrl);
    EXPECT_EQ(persisted->BackendState, status.BackendState);
    EXPECT_EQ(persisted->AuthorizationUrl, status.AuthorizationUrl);
}

TEST(Given_Registration, When_MachineApprovalIsRequired_Then_ApprovalStateIsPersisted)
{
    tailgate::test::LinuxTestHome home("linux-registration-approval");
    std::string pendingAuthKey = "tskey-auth-fake";
    std::string fallbackAuthKey = "tskey-auth-fallback-fake";
    std::string pendingAuthorizationUrl = "https://login.tailscale.com/a/fake-login-code";
    tailgate::linux_frontend::DaemonStatus status;
    tailgate::linux_frontend::Registration subject(
        pendingAuthKey, fallbackAuthKey, pendingAuthorizationUrl, status);
    const tailgate::control::client::RegistrationResult registration{
        .State = tailgate::control::client::RegistrationState::MachineApprovalRequired,
        .AuthorizationUrl = {},
        .AuthorizationCode = {},
        .ApprovalUrl = "https://login.tailscale.com/admin/machines",
        .Network = std::nullopt,
        .NetworkMapStreaming = false,
    };

    subject.StateChanged(registration);
    const auto persisted = tailgate::linux_frontend::ReadDaemonStatus();

    ASSERT_TRUE(persisted.has_value());
    EXPECT_TRUE(pendingAuthorizationUrl.empty());
    EXPECT_EQ(status.BackendState, "NeedsMachineAuth");
    EXPECT_FALSE(status.Online);
    EXPECT_EQ(status.AuthorizationUrl, registration.ApprovalUrl);
    EXPECT_EQ(persisted->BackendState, status.BackendState);
    EXPECT_EQ(persisted->AuthorizationUrl, status.AuthorizationUrl);
}

TEST(Given_Registration, When_RegistrationIsAccepted_Then_PendingStateIsCleared)
{
    tailgate::test::LinuxTestHome home("linux-registration-accepted");
    tailgate::linux_frontend::IdentityState identity;
    identity.MachinePrivateKey.fill(1);
    identity.NodePrivateKey.fill(2);
    identity.RegistrationComplete = false;
    tailgate::linux_frontend::WriteIdentity(identity);
    std::string pendingAuthKey = "tskey-auth-fake";
    std::string fallbackAuthKey = "tskey-auth-fallback-fake";
    std::string pendingAuthorizationUrl = "https://login.tailscale.com/a/fake-login-code";
    tailgate::linux_frontend::DaemonStatus status;
    status.AuthorizationUrl = pendingAuthorizationUrl;
    status.Error = "fake error";
    tailgate::linux_frontend::Registration subject(
        pendingAuthKey, fallbackAuthKey, pendingAuthorizationUrl, status);

    subject.Accepted();
    const auto persisted = tailgate::linux_frontend::ReadIdentity();

    ASSERT_TRUE(persisted.has_value());
    EXPECT_TRUE(pendingAuthKey.empty());
    EXPECT_TRUE(fallbackAuthKey.empty());
    EXPECT_TRUE(pendingAuthorizationUrl.empty());
    EXPECT_TRUE(status.AuthorizationUrl.empty());
    EXPECT_TRUE(status.Error.empty());
    EXPECT_TRUE(persisted->RegistrationComplete);
}

TEST(Given_Registration, When_ShutdownIsRequested_Then_RetryWaitIsInterrupted)
{
    tailgate::test::LinuxTestHome home("linux-registration-interrupted");
    std::string pendingAuthKey;
    std::string fallbackAuthKey;
    std::string pendingAuthorizationUrl;
    tailgate::linux_frontend::DaemonStatus status;
    tailgate::linux_frontend::Registration subject(
        pendingAuthKey, fallbackAuthKey, pendingAuthorizationUrl, status);
    tailgate::linux_frontend::Lifecycle::RequestStop();

    const bool retry = subject.WaitForRetry(std::chrono::seconds(1));
    tailgate::linux_frontend::Lifecycle::ClearStop();

    EXPECT_FALSE(retry);
}
