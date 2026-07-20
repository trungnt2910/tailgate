#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "app/view/impl/ExitNodeControlViewImpl.h"

#include "fakes/app/controller/FakeExitNodeController.h"
#include "fakes/app/controller/FakeNavigationController.h"
#include "fakes/app/controller/FakeSessionController.h"
#include "fakes/app/controller/FakeSettingsController.h"

#include "TestHost.h"
#include "ViewTestInjector.h"

namespace tailgate::uwp::tests
{
namespace
{

class Given_ExitNodeControlView : public testing::Test
{
protected:
    xaml::UIElement CreateSubject()
    {
        m_dependencies.Initialize();
        m_exitNode = std::make_shared<FakeExitNodeController>();
        m_navigation = std::make_shared<FakeNavigationController>();
        m_session = std::make_shared<FakeSessionController>();
        m_settings = std::make_shared<FakeSettingsController>();
        m_settings->GetState().Devices(std::vector<UwpDevice>{
            UwpDevice{.Name = L"online-exit.example.ts.net",
                      .Address = L"100.64.0.2",
                      .Online = true,
                      .ExitNodeOption = true},
            UwpDevice{.Name = L"offline-exit.example.ts.net",
                      .Address = L"100.64.0.3",
                      .Online = false,
                      .ExitNodeOption = true},
        });
        m_exitNode->GetState().Selection(L"online-exit.example.ts.net");
        m_subject = m_dependencies.Create<ExitNodeControlViewImpl>(
            di::bind<ExitNodeController>.to(
                [this](const auto&) -> ExitNodeController&
                {
                    return *m_exitNode;
                }),
            di::bind<NavigationController>.to(
                [this](const auto&) -> NavigationController&
                {
                    return *m_navigation;
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
    std::shared_ptr<FakeExitNodeController> m_exitNode;
    std::shared_ptr<FakeNavigationController> m_navigation;
    std::shared_ptr<FakeSessionController> m_session;
    std::shared_ptr<FakeSettingsController> m_settings;
    std::unique_ptr<ExitNodeControlViewImpl> m_subject;
};

TEST_F(Given_ExitNodeControlView, When_ExitNodesExist_Then_ExitNodePageMatchesGolden)
{
    TestHost::SetTestContentAsync(
        [this]() -> xaml::UIElement
        {
            return CreateSubject();
        })
        .get();

    const auto result = TestHost::CheckGolden(
        L"Given_ExitNodeControlView/When_ExitNodesExist_Then_ExitNodePageMatchesGolden.png");

    EXPECT_TRUE(result);
}

TEST_F(Given_ExitNodeControlView, When_NoExitNodesExist_Then_ExitNodePageMatchesGolden)
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
            m_settings->GetState().Devices({});
            m_exitNode->GetState().Selection(L"");
        });
    TestHost::WaitForIdleAsync().get();
    const auto result = TestHost::CheckGolden(
        L"Given_ExitNodeControlView/When_NoExitNodesExist_Then_ExitNodePageMatchesGolden.png");

    EXPECT_TRUE(result);
}

} // namespace
} // namespace tailgate::uwp::tests
