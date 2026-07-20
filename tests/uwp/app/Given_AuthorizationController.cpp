#include <memory>
#include <optional>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include "app/controller/impl/AuthorizationControllerImpl.h"

#include "fakes/app/controller/FakeSettingsController.h"
#include "fakes/app/controller/FakeSignInDialogController.h"

#include "TestHost.h"

namespace tailgate::uwp::tests
{
namespace
{

namespace di = boost::di;

class Given_AuthorizationController : public testing::Test
{
protected:
    void SetUp() override
    {
        m_settings = std::make_shared<FakeSettingsController>();
        m_signIn = std::make_shared<FakeSignInDialogController>();
        auto injector = di::make_injector(di::bind<SettingsController>.to(
                                              [this](const auto&) -> SettingsController&
                                              {
                                                  return *m_settings;
                                              }),
                                          di::bind<SignInDialogController>.to(
                                              [this](const auto&) -> SignInDialogController&
                                              {
                                                  return *m_signIn;
                                              }));
        m_subject = injector.create<std::unique_ptr<AuthorizationControllerImpl>>();
    }

    std::shared_ptr<FakeSettingsController> m_settings;
    std::shared_ptr<FakeSignInDialogController> m_signIn;
    std::unique_ptr<AuthorizationControllerImpl> m_subject;
};

TEST_F(Given_AuthorizationController, When_AcceptingAuthentication_Then_DialogValuesBecomePending)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_signIn->GetState().TailgateServer(L"https://example.com");
            m_signIn->GetState().AuthKey(L"test-auth-key");
            m_signIn->GetState().Hostname(L"test-device");
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->AcceptAuthentication();
        });

    EXPECT_EQ(m_subject->GetState().PendingTailgateServer(), L"https://example.com");
    EXPECT_EQ(m_subject->GetState().PendingAuthKey(), L"test-auth-key");
    EXPECT_EQ(m_subject->GetState().PendingHostname(),
              std::optional<winrt::hstring>(L"test-device"));
    EXPECT_EQ(m_settings->SetHostnameArgument, std::optional<winrt::hstring>(L"test-device"));
}

TEST_F(Given_AuthorizationController, When_FindingMatchingCache_Then_AuthorizationIsSelected)
{
    const AuthorizationCache cache{
        .Url = L"https://example.com/authorize",
        .TailgateServer = L"https://example.com",
        .AuthKey = L"test-auth-key",
        .Hostname = L"test-device",
        .MachineApproval = true,
    };
    TestHost::RunOnUiThread(
        [this, &cache]
        {
            m_subject->Cache(cache);
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->FindCached(L"https://example.com", L"test-auth-key", L"test-device");
        });

    EXPECT_EQ(m_subject->GetState().Authorization(), std::optional(cache));
    EXPECT_EQ(m_subject->GetState().MatchedAuthorization(), std::optional(cache));
}

} // namespace
} // namespace tailgate::uwp::tests
