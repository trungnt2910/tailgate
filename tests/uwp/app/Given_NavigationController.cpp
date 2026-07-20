#include <memory>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include "app/controller/impl/NavigationControllerImpl.h"

#include "TestHost.h"

namespace tailgate::uwp::tests
{
namespace
{

namespace di = boost::di;

class Given_NavigationController : public testing::Test
{
protected:
    void SetUp() override
    {
        auto injector = di::make_injector();
        m_subject = injector.create<std::unique_ptr<NavigationControllerImpl>>();
    }

    std::unique_ptr<NavigationControllerImpl> m_subject;
};

TEST_F(Given_NavigationController, When_GoingBack_Then_PreviousPageIsRestored)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->OpenPage(NavigationControllerState::Settings);
            m_subject->OpenPage(NavigationControllerState::Device);
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->Back();
        });

    EXPECT_EQ(m_subject->GetState().Current(), NavigationControllerState::Settings);
    EXPECT_TRUE(m_subject->GetState().CanGoBack());
}

TEST_F(Given_NavigationController, When_GoingHome_Then_HistoryIsCleared)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->OpenPage(NavigationControllerState::Accounts);
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->Home();
        });

    EXPECT_EQ(m_subject->GetState().Current(), NavigationControllerState::Home);
    EXPECT_FALSE(m_subject->GetState().CanGoBack());
}

} // namespace
} // namespace tailgate::uwp::tests
