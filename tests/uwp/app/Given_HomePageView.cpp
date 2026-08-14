#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "app/view/impl/HomePageViewImpl.h"

#include "fakes/app/controller/FakeClipboardController.h"
#include "fakes/app/controller/FakeDevicePageController.h"
#include "fakes/app/controller/FakeExitNodeController.h"
#include "fakes/app/controller/FakeHomePageController.h"
#include "fakes/app/controller/FakeNavigationController.h"
#include "fakes/app/controller/FakePingDialogController.h"
#include "fakes/app/controller/FakeProfilePictureController.h"
#include "fakes/app/controller/FakeSessionController.h"
#include "fakes/app/controller/FakeSettingsController.h"

#include "TestHost.h"
#include "ViewTestInjector.h"

namespace tailgate::uwp::tests
{
namespace
{

class Given_HomePageView : public testing::Test
{
protected:
    xaml::UIElement CreateSubject()
    {
        m_dependencies.Initialize();
        m_clipboard = std::make_shared<FakeClipboardController>();
        m_devicePage = std::make_shared<FakeDevicePageController>();
        m_exitNode = std::make_shared<FakeExitNodeController>();
        m_home = std::make_shared<FakeHomePageController>();
        m_navigation = std::make_shared<FakeNavigationController>();
        m_pingDialog = std::make_shared<FakePingDialogController>();
        m_profilePicture = std::make_shared<FakeProfilePictureController>();
        m_session = std::make_shared<FakeSessionController>();
        m_settings = std::make_shared<FakeSettingsController>();
        m_settings->GetState().TailnetDisplayName(L"Example Tailnet");
        m_settings->GetState().AccountDisplayName(L"Example User");
        m_settings->GetState().HasStoredProfile(true);
        m_settings->GetState().SelfAddress(L"100.64.0.1");
        m_settings->GetState().Devices(std::vector<UwpDevice>{
            UwpDevice{.Group = L"Example User",
                      .Name = L"local.example.ts.net",
                      .Address = L"100.64.0.1",
                      .Ipv6 = L"",
                      .OperatingSystem = L"Windows",
                      .Online = true,
                      .ExitNodeOption = false},
            UwpDevice{.Group = L"Example User",
                      .Name = L"peer.example.ts.net",
                      .Address = L"100.64.0.2",
                      .Ipv6 = L"",
                      .OperatingSystem = L"Linux",
                      .Online = true,
                      .ExitNodeOption = true},
            UwpDevice{.Group = L"Example User",
                      .Name = L"offline.example.ts.net",
                      .Address = L"100.64.0.3",
                      .Ipv6 = L"",
                      .OperatingSystem = L"Linux",
                      .Online = false,
                      .ExitNodeOption = false},
        });
        m_session->GetState().Connected(true);
        m_exitNode->GetState().Current(L"peer.example.ts.net");
        m_exitNode->GetState().Selection(L"peer.example.ts.net");
        m_subject = m_dependencies.Create<HomePageViewImpl>(
            di::bind<ClipboardController>.to(
                [this](const auto&) -> ClipboardController&
                {
                    return *m_clipboard;
                }),
            di::bind<DevicePageController>.to(
                [this](const auto&) -> DevicePageController&
                {
                    return *m_devicePage;
                }),
            di::bind<ExitNodeController>.to(
                [this](const auto&) -> ExitNodeController&
                {
                    return *m_exitNode;
                }),
            di::bind<HomePageController>.to(
                [this](const auto&) -> HomePageController&
                {
                    return *m_home;
                }),
            di::bind<NavigationController>.to(
                [this](const auto&) -> NavigationController&
                {
                    return *m_navigation;
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
            di::bind<SettingsController>.to(
                [this](const auto&) -> SettingsController&
                {
                    return *m_settings;
                }));
        return m_subject->Page();
    }

    ViewTestInjector m_dependencies;
    std::shared_ptr<FakeClipboardController> m_clipboard;
    std::shared_ptr<FakeDevicePageController> m_devicePage;
    std::shared_ptr<FakeExitNodeController> m_exitNode;
    std::shared_ptr<FakeHomePageController> m_home;
    std::shared_ptr<FakeNavigationController> m_navigation;
    std::shared_ptr<FakePingDialogController> m_pingDialog;
    std::shared_ptr<FakeProfilePictureController> m_profilePicture;
    std::shared_ptr<FakeSessionController> m_session;
    std::shared_ptr<FakeSettingsController> m_settings;
    std::unique_ptr<HomePageViewImpl> m_subject;
};

TEST_F(Given_HomePageView, When_Connected_Then_HomePageMatchesGolden)
{
    TestHost::SetTestContentAsync(
        [this]() -> xaml::UIElement
        {
            return CreateSubject();
        })
        .get();

    const auto result =
        TestHost::CheckGolden(L"Given_HomePageView/When_Connected_Then_HomePageMatchesGolden.png");

    EXPECT_TRUE(result);
}

TEST_F(Given_HomePageView, When_SignedOut_Then_HomePageMatchesGolden)
{
    TestHost::SetTestContentAsync(
        [this]() -> xaml::UIElement
        {
            return CreateSubject();
        })
        .get();

    TestHost::RunOnUiThread(
        [this]
        {
            m_session->GetState().Connected(false);
            m_settings->GetState().HasStoredProfile(false);
        });
    TestHost::WaitForIdleAsync().get();
    const auto result =
        TestHost::CheckGolden(L"Given_HomePageView/When_SignedOut_Then_HomePageMatchesGolden.png");

    EXPECT_TRUE(result);
}

} // namespace
} // namespace tailgate::uwp::tests
