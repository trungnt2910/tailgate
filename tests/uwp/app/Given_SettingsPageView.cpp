#include <memory>

#include <gtest/gtest.h>

#include "app/view/impl/SettingsPageViewImpl.h"

#include "fakes/app/controller/FakeClipboardController.h"
#include "fakes/app/controller/FakeNavigationController.h"
#include "fakes/app/controller/FakePackageController.h"
#include "fakes/app/controller/FakeProfilePictureController.h"
#include "fakes/app/controller/FakeSessionController.h"
#include "fakes/app/controller/FakeSettingsController.h"

#include "TestHost.h"
#include "ViewTestInjector.h"

namespace tailgate::uwp::tests
{
namespace
{

class Given_SettingsPageView : public testing::Test
{
protected:
    xaml::UIElement CreateSubject()
    {
        m_dependencies.Initialize();
        m_clipboard = std::make_shared<FakeClipboardController>();
        m_navigation = std::make_shared<FakeNavigationController>();
        m_package = std::make_shared<FakePackageController>();
        m_profilePicture = std::make_shared<FakeProfilePictureController>();
        m_session = std::make_shared<FakeSessionController>();
        m_settings = std::make_shared<FakeSettingsController>();
        m_settings->GetState().AccountDisplayName(L"Example User");
        m_settings->GetState().AccountName(L"user@example.com");
        m_settings->GetState().TailnetDisplayName(L"Example Tailnet");
        m_settings->GetState().TailgateServer(L"https://example.com");
        m_settings->GetState().HasStoredProfile(true);
        m_package->GetState().Major(1);
        m_package->GetState().Minor(2);
        m_package->GetState().Build(3);
        m_subject = m_dependencies.Create<SettingsPageViewImpl>(
            di::bind<ClipboardController>.to(
                [this](const auto&) -> ClipboardController&
                {
                    return *m_clipboard;
                }),
            di::bind<NavigationController>.to(
                [this](const auto&) -> NavigationController&
                {
                    return *m_navigation;
                }),
            di::bind<PackageController>.to(
                [this](const auto&) -> PackageController&
                {
                    return *m_package;
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
    std::shared_ptr<FakeNavigationController> m_navigation;
    std::shared_ptr<FakePackageController> m_package;
    std::shared_ptr<FakeProfilePictureController> m_profilePicture;
    std::shared_ptr<FakeSessionController> m_session;
    std::shared_ptr<FakeSettingsController> m_settings;
    std::unique_ptr<SettingsPageViewImpl> m_subject;
};

TEST_F(Given_SettingsPageView, When_SignedIn_Then_SettingsPageMatchesGolden)
{
    TestHost::SetTestContentAsync(
        [this]() -> xaml::UIElement
        {
            return CreateSubject();
        })
        .get();

    const auto result = TestHost::CheckGolden(
        L"Given_SettingsPageView/When_SignedIn_Then_SettingsPageMatchesGolden.png");

    EXPECT_TRUE(result);
}

TEST_F(Given_SettingsPageView, When_SignedOut_Then_SettingsPageMatchesGolden)
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
            m_settings->GetState().HasStoredProfile(false);
            m_settings->GetState().AccountName(L"");
            m_settings->GetState().AccountDisplayName(L"");
        });
    TestHost::WaitForIdleAsync().get();
    const auto result = TestHost::CheckGolden(
        L"Given_SettingsPageView/When_SignedOut_Then_SettingsPageMatchesGolden.png");

    EXPECT_TRUE(result);
}

} // namespace
} // namespace tailgate::uwp::tests
