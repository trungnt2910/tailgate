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
    EXPECT_EQ(m_interactive->ListenArgument, server);
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

} // namespace
} // namespace tailgate::uwp::tests
