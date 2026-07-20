#include <memory>

#include <gtest/gtest.h>

#include "app/view/impl/NodeAuthorizationDialogViewImpl.h"

#include "fakes/app/controller/FakeNodeAuthorizationDialogController.h"
#include "fakes/app/controller/FakeSessionController.h"

#include "TestHost.h"
#include "ViewTestInjector.h"

namespace tailgate::uwp::tests
{
namespace
{

class Given_NodeAuthorizationDialogView : public testing::Test
{
protected:
    xaml::UIElement CreateSubject(bool machineApproval = false)
    {
        m_dependencies.Initialize();
        m_controller = std::make_shared<FakeNodeAuthorizationDialogController>();
        m_session = std::make_shared<FakeSessionController>();
        m_controller->GetState().Url(L"https://login.tailscale.com/a/fake-login-url");
        m_controller->GetState().MachineApproval(machineApproval);
        m_subject = m_dependencies.Create<NodeAuthorizationDialogViewImpl>(
            di::bind<NodeAuthorizationDialogController>.to(
                [this](const auto&) -> NodeAuthorizationDialogController&
                {
                    return *m_controller;
                }),
            di::bind<SessionController>.to(
                [this](const auto&) -> SessionController&
                {
                    return *m_session;
                }));
        return m_subject->Dialog().Content().as<xaml::UIElement>();
    }

    ViewTestInjector m_dependencies;
    std::shared_ptr<FakeNodeAuthorizationDialogController> m_controller;
    std::shared_ptr<FakeSessionController> m_session;
    std::unique_ptr<NodeAuthorizationDialogViewImpl> m_subject;
};

TEST_F(Given_NodeAuthorizationDialogView, When_ApprovalIsRequired_Then_QrDialogMatchesGolden)
{
    const auto content = TestHost::SetTestContentAsync(
                             [this]() -> xaml::UIElement
                             {
                                 return CreateSubject(true);
                             })
                             .get();

    const auto result =
        TestHost::CheckGolden(content,
                              L"Given_NodeAuthorizationDialogView/"
                              L"When_ApprovalIsRequired_Then_QrDialogMatchesGolden.png");

    EXPECT_TRUE(result);
}

TEST_F(Given_NodeAuthorizationDialogView, When_LoginIsRequired_Then_QrDialogMatchesGolden)
{
    const auto content = TestHost::SetTestContentAsync(
                             [this]() -> xaml::UIElement
                             {
                                 return CreateSubject();
                             })
                             .get();
    const auto result =
        TestHost::CheckGolden(content,
                              L"Given_NodeAuthorizationDialogView/"
                              L"When_LoginIsRequired_Then_QrDialogMatchesGolden.png");

    EXPECT_TRUE(result);
}

} // namespace
} // namespace tailgate::uwp::tests
