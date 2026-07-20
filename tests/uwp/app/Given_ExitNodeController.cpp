#include <memory>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include "app/controller/impl/ExitNodeControllerImpl.h"

#include "fakes/app/controller/FakeSessionController.h"
#include "fakes/app/controller/FakeSettingsController.h"

#include "TestHost.h"

namespace tailgate::uwp::tests
{
namespace
{

namespace di = boost::di;

class Given_ExitNodeController : public testing::Test
{
protected:
    void SetUp() override
    {
        m_session = std::make_shared<FakeSessionController>();
        m_settings = std::make_shared<FakeSettingsController>();
        TestHost::RunOnUiThread(
            [this]
            {
                auto injector = di::make_injector(di::bind<SessionController>.to(
                                                      [this](const auto&) -> SessionController&
                                                      {
                                                          return *m_session;
                                                      }),
                                                  di::bind<SettingsController>.to(
                                                      [this](const auto&) -> SettingsController&
                                                      {
                                                          return *m_settings;
                                                      }));
                m_subject = injector.create<std::unique_ptr<ExitNodeControllerImpl>>();
            });
    }

    std::shared_ptr<FakeSessionController> m_session;
    std::shared_ptr<FakeSettingsController> m_settings;
    std::unique_ptr<ExitNodeControllerImpl> m_subject;
};

TEST_F(Given_ExitNodeController, When_UnknownNodeIsSelected_Then_NextConnectionUsesNoExitNode)
{
    const winrt::hstring unknownNode = L"unknown.example.ts.net";

    TestHost::RunOnUiThread(
        [this, &unknownNode]
        {
            m_subject->SetNodeForNextConnection(unknownNode);
        });

    const auto call = m_settings->LastSetExitNode.value_or(SetExitNodeCall{});
    EXPECT_TRUE(m_settings->LastSetExitNode.has_value());
    EXPECT_TRUE(call.exitNode.empty());
    EXPECT_FALSE(call.preserveSelection);
}

TEST_F(Given_ExitNodeController, When_KnownNodeIsSelected_Then_NextConnectionUsesThatNode)
{
    UwpDevice device;
    device.Name = L"exit.example.ts.net.";
    device.Address = L"100.64.0.2";
    device.ExitNodeOption = true;
    TestHost::RunOnUiThread(
        [this, &device]
        {
            m_settings->GetState().Devices({device});
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->SetNodeForNextConnection(L"exit");
        });

    ASSERT_TRUE(m_settings->LastSetExitNode.has_value());
    EXPECT_EQ(m_settings->LastSetExitNode->exitNode, L"exit");
    EXPECT_FALSE(m_settings->LastSetExitNode->preserveSelection);
}

TEST_F(Given_ExitNodeController, When_DisabledOffline_Then_SelectionIsPreserved)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_settings->GetState().ExitNode(L"exit.example.ts.net");
            m_settings->GetState().ExitNodeSelection(L"exit.example.ts.net");
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->SetEnabled(false);
        });

    ASSERT_TRUE(m_settings->LastSetExitNode.has_value());
    EXPECT_TRUE(m_settings->LastSetExitNode->exitNode.empty());
    EXPECT_TRUE(m_settings->LastSetExitNode->preserveSelection);
}

TEST_F(Given_ExitNodeController, When_ConnectionOperationIsActive_Then_ChangeIsIgnored)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_session->GetState().ConnectionOperationActive(true);
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->SetNode(L"");
        });

    EXPECT_FALSE(m_settings->LastSetExitNode.has_value());
    EXPECT_EQ(m_session->BeginExitNodeChangeCount, 0U);
}

TEST_F(Given_ExitNodeController, When_ConnectedWithoutSelfAddress_Then_TypedErrorIsReported)
{
    TestHost::RunOnUiThread(
        [this]
        {
            m_session->GetState().Connected(true);
        });

    TestHost::RunOnUiThread(
        [this]
        {
            m_subject->SetNode(L"");
        });

    ASSERT_TRUE(m_session->FinishExitNodeChangeError.has_value());
    EXPECT_EQ(m_session->BeginExitNodeChangeCount, 1U);
    EXPECT_EQ(*m_session->FinishExitNodeChangeError, UwpError::Code::VpnAddressUnavailable);
    EXPECT_EQ(m_settings->ReloadCount, 1U);
}

} // namespace
} // namespace tailgate::uwp::tests
