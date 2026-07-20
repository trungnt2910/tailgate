#include <memory>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include "app/view/impl/ContentDialogViewImpl.h"

#include "fakes/app/controller/FakeContentDialogController.h"
#include "fakes/app/view/FakeDialogViews.h"

#include "TestHost.h"

namespace tailgate::uwp::tests
{
namespace
{

namespace di = boost::di;

class Given_ContentDialogView : public testing::Test
{
protected:
    void SetUp() override
    {
        FakeNodeAuthorizationDialogView::OnClosedCount = 0;
        FakePingDialogView::OnClosedCount = 0;
        FakeSignInDialogView::OnClosedCount = 0;
        m_controller = std::make_shared<FakeContentDialogController>();
        TestHost::RunOnUiThread(
            [this]
            {
                auto injector = di::make_injector(
                    di::bind<ContentDialogController>.to(
                        [this](const auto&) -> ContentDialogController&
                        {
                            return *m_controller;
                        }),
                    di::bind<NodeAuthorizationDialogView>.to<FakeNodeAuthorizationDialogView>(),
                    di::bind<PingDialogView>.to<FakePingDialogView>(),
                    di::bind<SignInDialogView>.to<FakeSignInDialogView>());
                m_subject = injector.create<std::unique_ptr<ContentDialogViewImpl>>();
            });
    }

    std::shared_ptr<FakeContentDialogController> m_controller;
    std::unique_ptr<ContentDialogViewImpl> m_subject;
};

TEST_F(Given_ContentDialogView, When_SignInDialogIsHidden_Then_OnlyThatViewIsClosed)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_controller->ShowDialog(ContentDialogControllerState::SignIn);
        });
    TestHost::WaitForIdleAsync().get();
    TestHost::RunOnUiThread(
        [this]
        {
            m_controller->HideDialog(ContentDialogControllerState::SignIn);
        });
    TestHost::WaitForIdleAsync().get();

    EXPECT_EQ(FakeSignInDialogView::OnClosedCount, 1U);
    EXPECT_EQ(FakeNodeAuthorizationDialogView::OnClosedCount, 0U);
    EXPECT_EQ(FakePingDialogView::OnClosedCount, 0U);
}

TEST_F(Given_ContentDialogView, When_DialogTypeChanges_Then_OldAndNewViewsCloseInOrder)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_controller->ShowDialog(ContentDialogControllerState::SignIn);
        });
    TestHost::WaitForIdleAsync().get();
    TestHost::RunOnUiThread(
        [this]
        {
            m_controller->ShowDialog(ContentDialogControllerState::Ping);
        });
    TestHost::WaitForIdleAsync().get();
    TestHost::RunOnUiThread(
        [this]
        {
            m_controller->HideDialog(ContentDialogControllerState::Ping);
        });
    TestHost::WaitForIdleAsync().get();

    EXPECT_EQ(FakeSignInDialogView::OnClosedCount, 1U);
    EXPECT_EQ(FakePingDialogView::OnClosedCount, 1U);
    EXPECT_EQ(FakeNodeAuthorizationDialogView::OnClosedCount, 0U);
}

} // namespace
} // namespace tailgate::uwp::tests
