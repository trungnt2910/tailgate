#include <memory>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include "app/controller/impl/MainWindowControllerImpl.h"

#include "fakes/app/controller/FakeAuthorizationController.h"
#include "fakes/app/controller/FakeNavigationController.h"
#include "fakes/app/controller/FakeNodeAuthorizationDialogController.h"
#include "fakes/app/controller/FakePingDialogController.h"
#include "fakes/app/controller/FakeProfilePictureController.h"
#include "fakes/app/controller/FakeSessionController.h"
#include "fakes/app/controller/FakeSetOptionsController.h"
#include "fakes/app/controller/FakeSettingsController.h"
#include "fakes/app/controller/FakeSignInDialogController.h"

#include "TestHost.h"

namespace tailgate::uwp::tests
{
namespace
{

namespace di = boost::di;

class Given_MainWindowController : public testing::Test
{
protected:
    void SetUp() override
    {
        m_authorization = std::make_shared<FakeAuthorizationController>();
        m_navigation = std::make_shared<FakeNavigationController>();
        m_nodeDialog = std::make_shared<FakeNodeAuthorizationDialogController>();
        m_pingDialog = std::make_shared<FakePingDialogController>();
        m_profilePicture = std::make_shared<FakeProfilePictureController>();
        m_session = std::make_shared<FakeSessionController>();
        m_setOptions = std::make_shared<FakeSetOptionsController>();
        m_settings = std::make_shared<FakeSettingsController>();
        m_signIn = std::make_shared<FakeSignInDialogController>();
        TestHost::RunOnUiThread(
            [this]
            {
                auto injector =
                    di::make_injector(di::bind<AuthorizationController>.to(
                                          [this](const auto&) -> AuthorizationController&
                                          {
                                              return *m_authorization;
                                          }),
                                      di::bind<NavigationController>.to(
                                          [this](const auto&) -> NavigationController&
                                          {
                                              return *m_navigation;
                                          }),
                                      di::bind<NodeAuthorizationDialogController>.to(
                                          [this](const auto&) -> NodeAuthorizationDialogController&
                                          {
                                              return *m_nodeDialog;
                                          }),
                                      di::bind<PingDialogController>.to(
                                          [this](const auto&) -> PingDialogController&
                                          {
                                              return *m_pingDialog;
                                          }),
                                      di::bind<ProfilePictureController>.to(
                                          [this](const auto&) -> ProfilePictureController&
                                          {
                                              return *m_profilePicture;
                                          }),
                                      di::bind<SessionController>.to(
                                          [this](const auto&) -> SessionController&
                                          {
                                              return *m_session;
                                          }),
                                      di::bind<SetOptionsController>.to(
                                          [this](const auto&) -> SetOptionsController&
                                          {
                                              return *m_setOptions;
                                          }),
                                      di::bind<SettingsController>.to(
                                          [this](const auto&) -> SettingsController&
                                          {
                                              return *m_settings;
                                          }),
                                      di::bind<SignInDialogController>.to(
                                          [this](const auto&) -> SignInDialogController&
                                          {
                                              return *m_signIn;
                                          }));
                m_subject = injector.create<std::unique_ptr<MainWindowControllerImpl>>();
            });
    }

    std::shared_ptr<FakeAuthorizationController> m_authorization;
    std::shared_ptr<FakeNavigationController> m_navigation;
    std::shared_ptr<FakeNodeAuthorizationDialogController> m_nodeDialog;
    std::shared_ptr<FakePingDialogController> m_pingDialog;
    std::shared_ptr<FakeProfilePictureController> m_profilePicture;
    std::shared_ptr<FakeSessionController> m_session;
    std::shared_ptr<FakeSetOptionsController> m_setOptions;
    std::shared_ptr<FakeSettingsController> m_settings;
    std::shared_ptr<FakeSignInDialogController> m_signIn;
    std::unique_ptr<MainWindowControllerImpl> m_subject;
};

TEST_F(Given_MainWindowController, When_Activated_Then_ControllersRefreshAndNavigationReturnsHome)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_navigation->GetState().Current(NavigationControllerState::Settings);
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->Activate();
        });

    EXPECT_EQ(m_settings->ReloadCount, 1U);
    EXPECT_EQ(m_navigation->GetState().Current(), NavigationControllerState::Home);
    EXPECT_EQ(m_profilePicture->LoadCount, 1U);
    EXPECT_EQ(m_session->RefreshCount, 1U);
}

TEST_F(Given_MainWindowController, When_DownCommandActivates_Then_SessionDisconnects)
{
    tailgate::cli::Arguments arguments;
    arguments.SelectedCommand = tailgate::cli::Command::Down;
    m_subject->SetArguments(arguments);

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->Activate();
        });

    EXPECT_EQ(m_session->DisconnectCount, 1U);
    EXPECT_EQ(m_session->LogoutCount, 0U);
}

TEST_F(Given_MainWindowController, When_AuthenticatedUpCommandActivates_Then_SessionConnects)
{
    tailgate::cli::Arguments arguments;
    arguments.SelectedCommand = tailgate::cli::Command::Up;
    arguments.Up.TailgateUrl = "https://example.com";
    arguments.Up.AuthKey = "test-auth-key";
    arguments.Up.Hostname = "test-device";
    arguments.Up.HostnameSet = true;
    m_subject->SetArguments(arguments);

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->Activate();
        });

    ASSERT_TRUE(m_session->LastConnect.has_value());
    EXPECT_EQ(m_settings->SetHostnameArgument, L"test-device");
    EXPECT_EQ(m_authorization->SetPendingAuthenticationCount, 1U);
    EXPECT_EQ(m_session->LastConnect->tailgateServer, L"https://example.com");
    EXPECT_EQ(m_session->LastConnect->authKey, L"test-auth-key");
    EXPECT_TRUE(m_session->LastConnect->showDialogOnFailure);
    EXPECT_EQ(m_signIn->ShowCount, 0U);
}

TEST_F(Given_MainWindowController, When_UpCommandHasNoCredentials_Then_SignInIsShown)
{
    tailgate::cli::Arguments arguments;
    arguments.SelectedCommand = tailgate::cli::Command::Up;
    m_subject->SetArguments(arguments);

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->Activate();
        });

    EXPECT_FALSE(m_session->LastConnect.has_value());
    EXPECT_EQ(m_signIn->ShowCount, 1U);
    EXPECT_EQ(m_authorization->SetPendingAuthenticationCount, 1U);
}

TEST_F(Given_MainWindowController, When_KnownPeerIsPinged_Then_DialogReceivesResolvedDevice)
{
    UwpDevice self;
    self.Name = L"local.example.ts.net";
    self.Address = L"100.64.0.1";
    UwpDevice peer;
    peer.Name = L"peer.example.ts.net";
    peer.Address = L"100.64.0.2";
    TestHost::RunOnUiThread(
        [this, &self, &peer]
        {
            m_settings->GetState().Devices({self, peer});
        });
    tailgate::cli::Arguments arguments;
    arguments.SelectedCommand = tailgate::cli::Command::Ping;
    arguments.Ping.Target = "peer";
    m_subject->SetArguments(arguments);

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->Activate();
        });

    ASSERT_TRUE(m_pingDialog->LastShow.has_value());
    EXPECT_EQ(m_pingDialog->LastShow->deviceName, L"peer");
    EXPECT_EQ(m_pingDialog->LastShow->address, L"100.64.0.2");
    EXPECT_EQ(m_pingDialog->LastShow->selfAddress, L"100.64.0.1");
}

TEST_F(Given_MainWindowController, When_UnknownPeerIsPinged_Then_DialogIsNotShown)
{
    tailgate::cli::Arguments arguments;
    arguments.SelectedCommand = tailgate::cli::Command::Ping;
    arguments.Ping.Target = "missing";
    m_subject->SetArguments(arguments);

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->Activate();
        });

    EXPECT_EQ(m_pingDialog->ShowCount, 0U);
}

TEST_F(Given_MainWindowController, When_SignInIsAccepted_Then_AuthenticationAndConnectContinue)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_signIn->GetState().TailgateServer(L"https://example.com");
            m_signIn->GetState().AuthKey(L"test-auth-key");
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_signIn->GetState().Accepted(true);
        });

    ASSERT_TRUE(m_session->LastConnect.has_value());
    EXPECT_EQ(m_authorization->AcceptAuthenticationCount, 1U);
    EXPECT_EQ(m_session->LastConnect->tailgateServer, L"https://example.com");
    EXPECT_EQ(m_session->LastConnect->authKey, L"test-auth-key");
}

} // namespace
} // namespace tailgate::uwp::tests
