#include <memory>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include "app/controller/impl/SessionControllerImpl.h"

#include "fakes/app/controller/FakeAuthorizationController.h"
#include "fakes/app/controller/FakeControlPlaneController.h"
#include "fakes/app/controller/FakeInteractiveAuthorizationController.h"
#include "fakes/app/controller/FakeSettingsController.h"
#include "fakes/app/controller/FakeTailgateRelayController.h"
#include "fakes/app/controller/FakeVpnProfileController.h"

#include "TestHost.h"

namespace tailgate::uwp::tests
{
namespace
{

namespace di = boost::di;

class Given_SessionController : public testing::Test
{
protected:
    void SetUp() override
    {
        m_authorization = std::make_shared<FakeAuthorizationController>();
        m_controlPlane = std::make_shared<FakeControlPlaneController>();
        m_interactive = std::make_shared<FakeInteractiveAuthorizationController>();
        m_settings = std::make_shared<FakeSettingsController>();
        m_relay = std::make_shared<FakeTailgateRelayController>();
        m_vpn = std::make_shared<FakeVpnProfileController>();
        TestHost::RunOnUiThread(
            [this]
            {
                auto injector =
                    di::make_injector(di::bind<AuthorizationController>.to(
                                          [this](const auto&) -> AuthorizationController&
                                          {
                                              return *m_authorization;
                                          }),
                                      di::bind<ControlPlaneController>.to(
                                          [this](const auto&) -> ControlPlaneController&
                                          {
                                              return *m_controlPlane;
                                          }),
                                      di::bind<InteractiveAuthorizationController>.to(
                                          [this](const auto&) -> InteractiveAuthorizationController&
                                          {
                                              return *m_interactive;
                                          }),
                                      di::bind<SettingsController>.to(
                                          [this](const auto&) -> SettingsController&
                                          {
                                              return *m_settings;
                                          }),
                                      di::bind<TailgateRelayController>.to(
                                          [this](const auto&) -> TailgateRelayController&
                                          {
                                              return *m_relay;
                                          }),
                                      di::bind<VpnProfileController>.to(
                                          [this](const auto&) -> VpnProfileController&
                                          {
                                              return *m_vpn;
                                          }));
                m_subject = injector.create<std::unique_ptr<SessionControllerImpl>>();
            });
    }

    std::shared_ptr<FakeAuthorizationController> m_authorization;
    std::shared_ptr<FakeControlPlaneController> m_controlPlane;
    std::shared_ptr<FakeInteractiveAuthorizationController> m_interactive;
    std::shared_ptr<FakeSettingsController> m_settings;
    std::shared_ptr<FakeTailgateRelayController> m_relay;
    std::shared_ptr<FakeVpnProfileController> m_vpn;
    std::unique_ptr<SessionControllerImpl> m_subject;
};

TEST_F(Given_SessionController, When_ExternalVpnConnects_Then_SessionReflectsConnection)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_settings->GetState().HasStoredProfile(true);
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_vpn->GetState().Update(
                [](auto& state)
                {
                    state.Activity(VpnProfileActivity::Refreshing);
                    state.Connected(true);
                    state.Busy(false);
                });
        });

    EXPECT_TRUE(m_subject->GetState().Connected());
    EXPECT_FALSE(m_subject->GetState().Busy());
    EXPECT_FALSE(m_subject->GetState().ConnectionOperationActive());
    EXPECT_FALSE(m_vpn->ConnectServer.has_value());
}

TEST_F(Given_SessionController, When_ExternalVpnDisconnects_Then_SessionRetainsStoredProfile)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_settings->GetState().HasStoredProfile(true);
            m_vpn->GetState().Update(
                [](auto& state)
                {
                    state.Activity(VpnProfileActivity::Refreshing);
                    state.Connected(true);
                });
        });
    ASSERT_TRUE(m_subject->GetState().Connected());

    TestHost::RunOnUiThread(
        [this]
        {
            m_vpn->GetState().Connected(false);
        });

    EXPECT_FALSE(m_subject->GetState().Connected());
    EXPECT_FALSE(m_subject->GetState().Busy());
    EXPECT_TRUE(m_settings->GetState().HasStoredProfile());
    EXPECT_EQ(m_subject->GetState().SignInRequest(), 0U);
    EXPECT_EQ(m_vpn->LogoutCount, 0U);
}

TEST_F(Given_SessionController, When_ExitNodeChangeFinishes_Then_SessionReturnsToIdle)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->BeginExitNodeChange();
            m_subject->FinishExitNodeChange(std::nullopt);
        });

    EXPECT_FALSE(m_subject->GetState().ConnectionOperationActive());
    EXPECT_FALSE(m_subject->GetState().Busy());
    EXPECT_EQ(m_subject->GetState().Activity(), SessionActivity::Idle);
    EXPECT_FALSE(m_subject->GetState().Error().has_value());
}

TEST_F(Given_SessionController, When_UnvalidatedServerConnects_Then_RelayPreflightStarts)
{
    const winrt::hstring server = L"https://example.com";

    TestHost::RunOnUiThread(
        [this, &server]
        {
            m_subject->Connect(server, L"test-auth-key", true, false, std::nullopt);
        });

    ASSERT_TRUE(m_relay->LastPreflight.has_value());
    EXPECT_EQ(m_relay->LastPreflight->operationId, 1U);
    EXPECT_EQ(m_relay->LastPreflight->tailgateServer, server);
    EXPECT_TRUE(m_subject->GetState().ConnectionOperationActive());
    EXPECT_TRUE(m_subject->GetState().Busy());
    EXPECT_EQ(m_subject->GetState().Activity(), SessionActivity::Starting);
    EXPECT_FALSE(m_interactive->ListenArgument.has_value());
}

TEST_F(Given_SessionController, When_ValidatedServerConnects_Then_AuthorizationListenerStarts)
{
    const winrt::hstring server = L"https://example.com";
    TestHost::RunOnUiThread(
        [this, &server]
        {
            m_settings->GetState().ProfileValidated(true);
            m_settings->GetState().TailgateServer(server);
        });

    TestHost::RunOnUiThread(
        [this, &server]
        {
            m_subject->Connect(server, L"test-auth-key", false, false, std::nullopt);
        });

    EXPECT_FALSE(m_relay->LastPreflight.has_value());
    EXPECT_EQ(m_authorization->FindCachedCount, 1U);
    EXPECT_EQ(m_settings->SetAuthenticationTailgateServer, server);
    EXPECT_EQ(m_settings->SetAuthenticationAuthKey, L"test-auth-key");
    EXPECT_EQ(m_interactive->ListenArgument, L"test-profile");
}

TEST_F(Given_SessionController, When_ConnectIsRequestedDuringOperation_Then_LatestRequestIsPending)
{
    const winrt::hstring server = L"https://queued.example.com";
    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->BeginExitNodeChange();
        });

    TestHost::RunOnUiThread(
        [this, &server]
        {
            m_subject->Connect(server, L"queued-key", true, true, std::nullopt);
        });

    ASSERT_TRUE(m_subject->GetState().PendingConnect().has_value());
    EXPECT_EQ(m_subject->GetState().PendingConnect()->TailgateServer, server);
    EXPECT_EQ(m_subject->GetState().PendingConnect()->AuthKey, L"queued-key");
    EXPECT_TRUE(m_subject->GetState().PendingConnect()->ShowDialogOnFailure);
    EXPECT_TRUE(m_subject->GetState().PendingConnect()->RestartConnectedProfile);
    EXPECT_FALSE(m_relay->LastPreflight.has_value());
}

TEST_F(Given_SessionController, When_NoStoredProfileExists_Then_SignInIsRequested)
{
    const std::uint64_t initialRequest = m_subject->GetState().SignInRequest();

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->ConnectStoredOrRequestSignIn();
        });

    EXPECT_EQ(m_settings->ReloadCount, 1U);
    EXPECT_EQ(m_subject->GetState().SignInRequest(), initialRequest + 1);
    EXPECT_FALSE(m_subject->GetState().ConnectionOperationActive());
}

TEST_F(Given_SessionController, When_DisconnectStarts_Then_VpnDisconnectAndBusyStateAreSet)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->Disconnect();
        });

    EXPECT_EQ(m_vpn->DisconnectCount, 1U);
    EXPECT_TRUE(m_subject->GetState().ConnectionOperationActive());
    EXPECT_TRUE(m_subject->GetState().Busy());
    EXPECT_EQ(m_subject->GetState().Activity(), SessionActivity::Stopping);
}

TEST_F(Given_SessionController, When_ConnectionAttemptIsCancelled_Then_BothListenersAreCancelled)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->CancelActiveConnectionAttempt();
        });

    EXPECT_EQ(m_interactive->CancelCount, 1U);
    EXPECT_EQ(m_vpn->CancelConnectCount, 1U);
}

TEST_F(Given_SessionController, When_ConnectArrivesDuringProfileRefresh_Then_RequestWaits)
{
    const winrt::hstring server = L"https://example.com";
    TestHost::RunOnUiThread(
        [&]
        {
            m_vpn->GetState().Update(
                [](auto& state)
                {
                    state.Activity(VpnProfileActivity::Refreshing);
                    state.Busy(true);
                });
        });

    TestHost::RunOnUiThread(
        [&]
        {
            m_subject->Connect(server, L"", false, false, std::nullopt);
        });

    EXPECT_TRUE(m_subject->GetState().PendingConnect().has_value());
    EXPECT_FALSE(m_subject->GetState().ConnectionOperationActive());
    EXPECT_FALSE(m_relay->LastPreflight.has_value());
    EXPECT_FALSE(m_vpn->ConnectServer.has_value());
}

TEST_F(Given_SessionController, When_ProfileRefreshCompletes_Then_QueuedConnectStarts)
{
    const winrt::hstring server = L"https://example.com";
    TestHost::RunOnUiThread(
        [&]
        {
            m_vpn->GetState().Update(
                [](auto& state)
                {
                    state.Activity(VpnProfileActivity::Refreshing);
                    state.Busy(true);
                });
            m_subject->Connect(server, L"", false, false, std::nullopt);
        });

    TestHost::RunOnUiThread(
        [&]
        {
            m_vpn->GetState().Busy(false);
        });

    EXPECT_FALSE(m_subject->GetState().PendingConnect().has_value());
    EXPECT_TRUE(m_subject->GetState().ConnectionOperationActive());
    EXPECT_TRUE(m_relay->LastPreflight.has_value());
}

TEST_F(Given_SessionController,
       When_DisconnectArrivesDuringProfileRefresh_Then_ItWaitsForCompletion)
{
    TestHost::RunOnUiThread(
        [&]
        {
            m_vpn->GetState().Update(
                [](auto& state)
                {
                    state.Activity(VpnProfileActivity::Refreshing);
                    state.Busy(true);
                });
        });
    std::size_t prematureDisconnects = 0;

    TestHost::RunOnUiThread(
        [&]
        {
            m_subject->Disconnect();
            prematureDisconnects = m_vpn->DisconnectCount;
            m_vpn->GetState().Busy(false);
        });

    EXPECT_EQ(prematureDisconnects, 0U);
    EXPECT_EQ(m_vpn->DisconnectCount, 1U);
    EXPECT_TRUE(m_subject->GetState().ConnectionOperationActive());
}

TEST_F(Given_SessionController,
       When_DisconnectSupersedesConnectDuringRefresh_Then_OnlyDisconnectRuns)
{
    TestHost::RunOnUiThread(
        [&]
        {
            m_vpn->GetState().Update(
                [](auto& state)
                {
                    state.Activity(VpnProfileActivity::Refreshing);
                    state.Busy(true);
                });
            m_subject->Connect(L"https://example.com", L"", false, false, std::nullopt);
        });

    TestHost::RunOnUiThread(
        [&]
        {
            m_subject->Disconnect();
            m_vpn->GetState().Busy(false);
        });

    EXPECT_EQ(m_vpn->DisconnectCount, 1U);
    EXPECT_FALSE(m_relay->LastPreflight.has_value());
    EXPECT_FALSE(m_subject->GetState().PendingConnect().has_value());
}

TEST_F(Given_SessionController, When_ConnectSupersedesDisconnectDuringRefresh_Then_OnlyConnectRuns)
{
    TestHost::RunOnUiThread(
        [&]
        {
            m_vpn->GetState().Update(
                [](auto& state)
                {
                    state.Activity(VpnProfileActivity::Refreshing);
                    state.Busy(true);
                });
            m_subject->Disconnect();
        });

    TestHost::RunOnUiThread(
        [&]
        {
            m_subject->Connect(L"https://example.com", L"", false, false, std::nullopt);
            m_vpn->GetState().Busy(false);
        });

    EXPECT_EQ(m_vpn->DisconnectCount, 0U);
    EXPECT_TRUE(m_relay->LastPreflight.has_value());
    EXPECT_FALSE(m_subject->GetState().PendingConnect().has_value());
}

TEST_F(Given_SessionController, When_RelayIsEmpty_Then_NativeAuthorizationSkipsPreflight)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->Connect(L"", L"test-auth-key", false, false, std::nullopt);
        });

    EXPECT_FALSE(m_relay->LastPreflight);
    EXPECT_EQ(m_settings->SetAuthenticationTailgateServer, L"");
    EXPECT_EQ(m_interactive->ListenArgument, L"test-profile");
    EXPECT_FALSE(m_vpn->ConnectServer);
}

TEST_F(Given_SessionController, When_NativeListenerIsReady_Then_ConnectsWithoutRelay)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->Connect(L"", L"", false, false, std::nullopt);
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_interactive->GetState().Update(
                [](auto& state)
                {
                    state.ProfileId(L"test-profile");
                    state.Status(InteractiveAuthorizationStatus::Listening);
                });
        });

    EXPECT_EQ(m_vpn->ConnectServer, L"");
    EXPECT_FALSE(m_relay->LastPreflight);
}

TEST_F(Given_SessionController,
       When_ListenerFailsDuringStatusRefresh_Then_FinishesConnectionAttempt)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_settings->GetState().HasStoredProfile(true);
            m_subject->Connect(L"", L"", false, false, std::nullopt);
            m_vpn->GetState().Update(
                [](auto& state)
                {
                    state.Activity(VpnProfileActivity::Refreshing);
                    state.Busy(true);
                });
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_interactive->GetState().Update(
                [](auto& state)
                {
                    state.ProfileId(L"test-profile");
                    state.Status(InteractiveAuthorizationStatus::Failed);
                    state.Error(UwpError::Code::Unexpected);
                });
        });

    EXPECT_FALSE(m_subject->GetState().ConnectionOperationActive());
    EXPECT_FALSE(m_subject->GetState().Busy());
    EXPECT_EQ(m_subject->GetState().Error(), UwpError::Code::Unexpected);
    EXPECT_EQ(m_vpn->CancelConnectCount, 0U);
}

TEST_F(Given_SessionController, When_AnotherProfileListenerReportsReady_Then_DoesNotConnect)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->Connect(L"", L"", false, false, std::nullopt);
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_interactive->GetState().Update(
                [](auto& state)
                {
                    state.ProfileId(L"other-profile");
                    state.Status(InteractiveAuthorizationStatus::Listening);
                });
        });

    EXPECT_FALSE(m_vpn->ConnectServer);
    EXPECT_TRUE(m_subject->GetState().ConnectionOperationActive());
}

TEST_F(Given_SessionController, When_StoredNativeProfileConnects_Then_ReusesItsIdentity)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_settings->GetState().ProfileId(L"stored-profile");
            m_settings->GetState().ProfileValidated(true);
            m_settings->GetState().HasStoredProfile(true);
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->ConnectStoredOrRequestSignIn();
        });

    EXPECT_EQ(m_interactive->ListenArgument, L"stored-profile");
    EXPECT_EQ(m_subject->GetState().SignInRequest(), 0U);
    EXPECT_FALSE(m_relay->LastPreflight);
}

TEST_F(Given_SessionController, When_RelayPreflightFails_Then_RestoresPreviousNativeConnection)
{
    ConnectionSettingsSnapshot previous;
    previous.TailgateServer = L"";
    TestHost::RunOnUiThread(
        [this, &previous]
        {
            m_settings->GetState().ProfileId(L"stored-profile");
            m_settings->GetState().HasStoredProfile(true);
            m_subject->Connect(L"https://example.com", L"", false, true, previous);
        });
    ASSERT_TRUE(m_relay->LastPreflight);
    const auto operation = m_relay->LastPreflight->operationId;

    TestHost::RunOnUiThread(
        [this, operation]
        {
            m_relay->GetState().Update(
                [operation](auto& state)
                {
                    state.OperationId(operation);
                    state.Error(UwpError::Code::RelayConnectionFailed);
                    state.Busy(false);
                });
        });

    EXPECT_EQ(m_settings->RestoreConnectionSettingsArgument, previous);
    EXPECT_EQ(m_settings->SetAuthenticationTailgateServer, L"");
    EXPECT_EQ(m_interactive->ListenArgument, L"stored-profile");
    EXPECT_EQ(m_relay->LastPreflight->operationId, operation);
}

TEST_F(Given_SessionController,
       When_PolicyRestartIsRequestedForConnectedProfile_Then_UsesExistingConnectWorkflow)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_settings->GetState().ProfileId(L"test-profile");
            m_settings->GetState().ProfileValidated(true);
            m_vpn->GetState().Update(
                [](auto& state)
                {
                    state.Activity(VpnProfileActivity::Refreshing);
                    state.Busy(false);
                    state.Connected(true);
                });
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_settings->GetState().PolicyRestartRequired(true);
        });

    EXPECT_TRUE(m_subject->GetState().ConnectionOperationActive());
    EXPECT_EQ(m_subject->GetState().Activity(), SessionActivity::Starting);
    EXPECT_EQ(m_interactive->ListenArgument, L"test-profile");
}

TEST_F(Given_SessionController,
       When_RefreshCompletesDuringExitNodeChange_Then_PolicyRestartStillStarts)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_settings->GetState().ProfileId(L"test-profile");
            m_settings->GetState().ProfileValidated(true);
            m_vpn->GetState().Update(
                [](auto& state)
                {
                    state.Activity(VpnProfileActivity::Refreshing);
                    state.Busy(false);
                    state.Connected(true);
                });
            m_subject->BeginExitNodeChange();
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_vpn->GetState().Update(
                [](auto& state)
                {
                    state.Activity(VpnProfileActivity::Refreshing);
                    state.Busy(false);
                    state.Connected(true);
                });
            m_settings->GetState().PolicyRestartRequired(true);
        });

    EXPECT_TRUE(m_subject->GetState().ConnectionOperationActive());
    EXPECT_EQ(m_subject->GetState().Activity(), SessionActivity::Starting);
    EXPECT_EQ(m_interactive->ListenArgument, L"test-profile");
}

TEST_F(Given_SessionController,
       When_PolicyRestartIsPendingAfterUserDisconnected_Then_DoesNotReconnect)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_settings->GetState().PolicyRestartRequired(true);
        });

    EXPECT_FALSE(m_subject->GetState().ConnectionOperationActive());
    EXPECT_FALSE(m_interactive->ListenArgument);
}

TEST_F(Given_SessionController,
       When_DisconnectedRefreshArrivesBeforePolicyRestart_Then_ExitNodeRestartStillStarts)
{
    TestHost::RunOnUiThread(
        [&]
        {
            m_vpn->GetState().Update(
                [](auto& state)
                {
                    state.Activity(VpnProfileActivity::Refreshing);
                    state.Connected(true);
                    state.Busy(false);
                });
            m_subject->BeginExitNodeChange();
        });

    TestHost::RunOnUiThread(
        [&]
        {
            m_vpn->GetState().Update(
                [](auto& state)
                {
                    state.Activity(VpnProfileActivity::Refreshing);
                    state.Connected(false);
                    state.Busy(false);
                });
            m_settings->GetState().PolicyRestartRequired(true);
        });

    EXPECT_TRUE(m_subject->GetState().ConnectionOperationActive());
    EXPECT_EQ(m_subject->GetState().Activity(), SessionActivity::Starting);
    EXPECT_EQ(m_interactive->ListenArgument, L"test-profile");
}

TEST_F(Given_SessionController,
       When_PolicyRestartArrivesDuringRefresh_Then_ExitNodeRestartStillStarts)
{
    TestHost::RunOnUiThread(
        [&]
        {
            m_vpn->GetState().Update(
                [](auto& state)
                {
                    state.Activity(VpnProfileActivity::Refreshing);
                    state.Connected(true);
                    state.Busy(false);
                });
            m_subject->BeginExitNodeChange();
        });

    TestHost::RunOnUiThread(
        [&]
        {
            m_vpn->GetState().Busy(true);
            m_settings->GetState().PolicyRestartRequired(true);
            m_vpn->GetState().Update(
                [](auto& state)
                {
                    state.Activity(VpnProfileActivity::Refreshing);
                    state.Connected(false);
                    state.Busy(false);
                });
        });

    EXPECT_TRUE(m_subject->GetState().ConnectionOperationActive());
    EXPECT_EQ(m_subject->GetState().Activity(), SessionActivity::Starting);
    EXPECT_EQ(m_interactive->ListenArgument, L"test-profile");
}

TEST_F(Given_SessionController,
       When_ExitNodeAcknowledgementArrivesDuringDial_Then_DialRetainsWorkflowOwnership)
{
    TestHost::RunOnUiThread(
        [&]
        {
            m_subject->Connect(L"", L"", false, true, std::nullopt);
            m_interactive->GetState().Update(
                [](auto& state)
                {
                    state.ProfileId(L"test-profile");
                    state.Status(InteractiveAuthorizationStatus::Listening);
                });
        });
    ASSERT_TRUE(m_vpn->ConnectServer.has_value());

    TestHost::RunOnUiThread(
        [&]
        {
            m_subject->FinishExitNodeChange(std::nullopt);
        });

    EXPECT_TRUE(m_subject->GetState().ConnectionOperationActive());
    EXPECT_TRUE(m_subject->GetState().Busy());
    EXPECT_EQ(m_subject->GetState().Activity(), SessionActivity::Starting);
    EXPECT_EQ(m_vpn->RefreshCount, 0U);
}

TEST_F(Given_SessionController,
       When_ExitNodeTimeoutArrivesDuringDial_Then_DialRetainsWorkflowOwnership)
{
    TestHost::RunOnUiThread(
        [&]
        {
            m_subject->Connect(L"", L"", false, true, std::nullopt);
            m_interactive->GetState().Update(
                [](auto& state)
                {
                    state.ProfileId(L"test-profile");
                    state.Status(InteractiveAuthorizationStatus::Listening);
                });
        });
    ASSERT_TRUE(m_vpn->ConnectServer.has_value());

    TestHost::RunOnUiThread(
        [&]
        {
            m_subject->FinishExitNodeChange(UwpError::Code::VpnBackgroundRestartTimedOut);
        });

    EXPECT_TRUE(m_subject->GetState().ConnectionOperationActive());
    EXPECT_TRUE(m_subject->GetState().Busy());
    EXPECT_EQ(m_subject->GetState().Activity(), SessionActivity::Starting);
    EXPECT_EQ(m_vpn->RefreshCount, 0U);
}

TEST_F(Given_SessionController,
       When_ExitNodeErrorPrecedesSuccessfulRedial_Then_ErrorRemainsVisibleAfterCompletion)
{
    TestHost::RunOnUiThread(
        [&]
        {
            m_subject->Connect(L"", L"", false, true, std::nullopt);
            m_interactive->GetState().Update(
                [](auto& state)
                {
                    state.ProfileId(L"test-profile");
                    state.Status(InteractiveAuthorizationStatus::Listening);
                });
        });
    ASSERT_TRUE(m_vpn->ConnectServer.has_value());

    TestHost::RunOnUiThread(
        [&]
        {
            m_subject->FinishExitNodeChange(UwpError::Code::ExitNodeRejected);
            m_vpn->GetState().Update(
                [](auto& state)
                {
                    state.Activity(VpnProfileActivity::Connecting);
                    state.Connected(true);
                    state.Busy(false);
                });
        });

    EXPECT_TRUE(m_subject->GetState().Connected());
    EXPECT_FALSE(m_subject->GetState().ConnectionOperationActive());
    EXPECT_FALSE(m_subject->GetState().Busy());
    EXPECT_EQ(m_subject->GetState().Error(), UwpError::Code::ExitNodeRejected);
}

} // namespace
} // namespace tailgate::uwp::tests
