#include <memory>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include <tailgate/cli/Arguments.h>

#include "app/controller/impl/SetOptionsControllerImpl.h"

#include "fakes/app/controller/FakeExitNodeController.h"
#include "fakes/app/controller/FakeSessionController.h"
#include "fakes/app/controller/FakeSettingsController.h"

#include "TestHost.h"

namespace tailgate::uwp::tests
{
namespace
{

namespace di = boost::di;

class Given_SetOptionsController : public testing::Test
{
protected:
    void SetUp() override
    {
        m_exitNode = std::make_shared<FakeExitNodeController>();
        m_session = std::make_shared<FakeSessionController>();
        m_settings = std::make_shared<FakeSettingsController>();
        auto injector = di::make_injector(di::bind<ExitNodeController>.to(
                                              [this](const auto&) -> ExitNodeController&
                                              {
                                                  return *m_exitNode;
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
        m_subject = injector.create<std::unique_ptr<SetOptionsControllerImpl>>();
    }

    std::shared_ptr<FakeExitNodeController> m_exitNode;
    std::shared_ptr<FakeSessionController> m_session;
    std::shared_ptr<FakeSettingsController> m_settings;
    std::unique_ptr<SetOptionsControllerImpl> m_subject;
};

TEST_F(Given_SetOptionsController, When_Disconnected_Then_OptionsApplyToNextConnection)
{
    tailgate::cli::SetOptions options;
    options.TailgateUrl = "https://example.com";
    options.Hostname = "test-device";
    options.ExitNode = "exit.example.ts.net";

    TestHost::RunOnUiThread(
        [this, &options]
        {
            m_subject->Apply(options);
        });

    EXPECT_EQ(m_settings->ReloadCount, 1U);
    EXPECT_EQ(m_settings->SetTailgateServerArgument,
              std::optional<winrt::hstring>(L"https://example.com"));
    EXPECT_EQ(m_settings->SetHostnameArgument, std::optional<winrt::hstring>(L"test-device"));
    EXPECT_EQ(m_exitNode->SetNodeForNextConnectionArgument,
              std::optional<winrt::hstring>(L"exit.example.ts.net"));
    EXPECT_FALSE(m_exitNode->SetNodeArgument.has_value());
    EXPECT_FALSE(m_session->LastConnect.has_value());
}

TEST_F(Given_SetOptionsController, When_ConnectionIsActive_Then_OptionsAreIgnored)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_session->GetState().ConnectionOperationActive(true);
        });
    tailgate::cli::SetOptions options;
    options.Hostname = "ignored-device";

    TestHost::RunOnUiThread(
        [this, &options]
        {
            m_subject->Apply(options);
        });

    EXPECT_EQ(m_settings->ReloadCount, 0U);
    EXPECT_FALSE(m_settings->SetHostnameArgument.has_value());
    EXPECT_FALSE(m_session->LastConnect.has_value());
}

} // namespace
} // namespace tailgate::uwp::tests
