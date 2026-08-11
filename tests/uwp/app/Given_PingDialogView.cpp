#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "app/view/impl/PingDialogViewImpl.h"

#include "fakes/app/controller/FakePingController.h"
#include "fakes/app/controller/FakePingDialogController.h"

#include "TestHost.h"
#include "ViewTestInjector.h"

namespace tailgate::uwp::tests
{

class Given_PingDialogView : public testing::Test
{
protected:
    xaml::UIElement CreateSubject(PingStatus status = PingStatus::Success, bool direct = true)
    {
        m_dependencies.Initialize();
        m_ping = std::make_shared<FakePingController>();
        m_pingDialog = std::make_shared<FakePingDialogController>();
        m_pingDialog->GetState().DeviceName(L"peer");
        m_ping->GetState().Status(status);
        m_ping->GetState().LatencyMilliseconds(12.4);
        m_ping->GetState().Direct(direct);
        m_ping->GetState().Relay(direct ? L"" : L"SYD");
        m_ping->GetState().Samples(status == PingStatus::Success
                                       ? std::vector<double>{14.0, 12.0, 11.0, 12.4}
                                       : std::vector<double>{});
        m_subject = m_dependencies.Create<PingDialogViewImpl>(
            di::bind<PingController>.to(
                [this](const auto&) -> PingController&
                {
                    return *m_ping;
                }),
            di::bind<PingDialogController>.to(
                [this](const auto&) -> PingDialogController&
                {
                    return *m_pingDialog;
                }));
        return m_subject->Dialog().Content().as<xaml::UIElement>();
    }

    ViewTestInjector m_dependencies;
    std::shared_ptr<FakePingController> m_ping;
    std::shared_ptr<FakePingDialogController> m_pingDialog;
    std::unique_ptr<PingDialogViewImpl> m_subject;
};

TEST_F(Given_PingDialogView, When_DirectPingSucceeds_Then_PingDialogMatchesGolden)
{
    const auto content = TestHost::SetTestContentAsync(
                             [this]() -> xaml::UIElement
                             {
                                 return CreateSubject();
                             })
                             .get();

    const auto result = TestHost::CheckGolden(
        content, L"Given_PingDialogView/When_DirectPingSucceeds_Then_PingDialogMatchesGolden.png");

    EXPECT_TRUE(result);
}

TEST_F(Given_PingDialogView, When_PingTimesOut_Then_PingDialogMatchesGolden)
{
    const auto content = TestHost::SetTestContentAsync(
                             [this]() -> xaml::UIElement
                             {
                                 return CreateSubject(PingStatus::Timeout);
                             })
                             .get();

    const auto result = TestHost::CheckGolden(
        content, L"Given_PingDialogView/When_PingTimesOut_Then_PingDialogMatchesGolden.png");

    EXPECT_TRUE(result);
}

TEST_F(Given_PingDialogView, When_RelayedPingSucceeds_Then_PingDialogMatchesGolden)
{
    const auto content = TestHost::SetTestContentAsync(
                             [this]() -> xaml::UIElement
                             {
                                 return CreateSubject(PingStatus::Success, false);
                             })
                             .get();

    const auto result = TestHost::CheckGolden(
        content, L"Given_PingDialogView/When_RelayedPingSucceeds_Then_PingDialogMatchesGolden.png");

    EXPECT_TRUE(result);
}

TEST_F(Given_PingDialogView, When_DialogCloses_Then_ControllerIsNotified)
{
    TestHost::RunOnUiThread(
        [this]
        {
            (void)CreateSubject();
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->OnClosed(controls::ContentDialogResult::None);
        });

    EXPECT_EQ(m_pingDialog->OnClosedCount, 1U);
}

} // namespace tailgate::uwp::tests
