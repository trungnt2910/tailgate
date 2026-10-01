#include <string>

#include <gtest/gtest.h>

#include <tailgate/control/client/ControlClient.h>

#include "manager/ControlRegistrationNotification.h"

namespace tailgate::uwp::tests
{
namespace
{

constexpr auto ProfileId = "test-profile";

TEST(Given_ControlRegistrationNotification,
     When_LoginIsRequired_Then_ControlAuthorizationUrlIsForwarded)
{
    tailgate::control::client::RegistrationResult registration;
    registration.State = tailgate::control::client::RegistrationState::LoginRequired;
    registration.AuthorizationUrl = "https://login.tailscale.com/a/fake-login-code";

    const auto notification = bg::manager::BuildAuthenticationNotification(registration, ProfileId);
    ASSERT_TRUE(notification.has_value());

    EXPECT_EQ(notification->Kind, bg::manager::ForegroundConnectionKind::LoginRequired);
    EXPECT_EQ(notification->Url, registration.AuthorizationUrl);
    EXPECT_EQ(notification->ProfileId, ProfileId);
}

TEST(Given_ControlRegistrationNotification,
     When_MachineApprovalIsRequired_Then_ControlApprovalUrlIsForwarded)
{
    tailgate::control::client::RegistrationResult registration;
    registration.State = tailgate::control::client::RegistrationState::MachineApprovalRequired;
    registration.ApprovalUrl = "https://login.tailscale.com/admin/machines/fake-machine";

    const auto notification = bg::manager::BuildAuthenticationNotification(registration, ProfileId);
    ASSERT_TRUE(notification.has_value());

    EXPECT_EQ(notification->Kind, bg::manager::ForegroundConnectionKind::MachineApprovalRequired);
    EXPECT_EQ(notification->Url, registration.ApprovalUrl);
    EXPECT_EQ(notification->ProfileId, ProfileId);
}

TEST(Given_ControlRegistrationNotification,
     When_ControlRegistrationIsComplete_Then_NoAuthenticationNotificationIsBuilt)
{
    tailgate::control::client::RegistrationResult registration;
    registration.State = tailgate::control::client::RegistrationState::Complete;

    const auto notification = bg::manager::BuildAuthenticationNotification(registration, ProfileId);

    EXPECT_FALSE(notification.has_value());
}

} // namespace
} // namespace tailgate::uwp::tests
