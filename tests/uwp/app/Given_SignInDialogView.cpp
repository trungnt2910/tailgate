#include <memory>

#include <gtest/gtest.h>

#include "app/view/impl/SignInDialogViewImpl.h"

#include "fakes/app/controller/FakeSignInDialogController.h"

#include "TestHost.h"
#include "ViewTestInjector.h"

namespace tailgate::uwp::tests
{
namespace
{

class Given_SignInDialogView : public testing::Test
{
protected:
    xaml::UIElement CreateSubject(bool advancedExpanded = true, bool validationErrorVisible = false)
    {
        m_dependencies.Initialize();
        m_controller = std::make_shared<FakeSignInDialogController>();
        m_controller->GetState().TailgateServer(validationErrorVisible ? L""
                                                                       : L"https://example.com");
        m_controller->GetState().AuthKey(L"test-auth-key");
        m_controller->GetState().Hostname(L"test-device");
        m_controller->GetState().AdvancedExpanded(advancedExpanded);
        m_controller->GetState().ValidationErrorVisible(validationErrorVisible);
        m_subject = m_dependencies.Create<SignInDialogViewImpl>(di::bind<SignInDialogController>.to(
            [this](const auto&) -> SignInDialogController&
            {
                return *m_controller;
            }));
        return m_subject->Dialog().Content().as<xaml::UIElement>();
    }

    ViewTestInjector m_dependencies;
    std::shared_ptr<FakeSignInDialogController> m_controller;
    std::unique_ptr<SignInDialogViewImpl> m_subject;
};

TEST_F(Given_SignInDialogView, When_AdvancedFieldsAreVisible_Then_SignInDialogMatchesGolden)
{
    const auto content = TestHost::SetTestContentAsync(
                             [this]() -> xaml::UIElement
                             {
                                 return CreateSubject();
                             })
                             .get();

    const auto result =
        TestHost::CheckGolden(content,
                              L"Given_SignInDialogView/"
                              L"When_AdvancedFieldsAreVisible_Then_SignInDialogMatchesGolden.png");

    EXPECT_TRUE(result);
}

TEST_F(Given_SignInDialogView, When_ServerIsMissing_Then_ValidationStateMatchesGolden)
{
    const auto content = TestHost::SetTestContentAsync(
                             [this]() -> xaml::UIElement
                             {
                                 return CreateSubject(false, true);
                             })
                             .get();

    const auto result = TestHost::CheckGolden(
        content,
        L"Given_SignInDialogView/When_ServerIsMissing_Then_ValidationStateMatchesGolden.png");

    EXPECT_TRUE(result);
}

TEST_F(Given_SignInDialogView, When_DialogCloses_Then_ControllerReceivesResult)
{
    TestHost::RunOnUiThread(
        [this]
        {
            (void)CreateSubject();
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->OnClosed(controls::ContentDialogResult::Primary);
        });

    EXPECT_EQ(m_controller->OnClosedArgument,
              std::optional(controls::ContentDialogResult::Primary));
}

} // namespace
} // namespace tailgate::uwp::tests
