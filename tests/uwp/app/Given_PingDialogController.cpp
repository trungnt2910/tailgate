#include <memory>

#include <boost/di.hpp>
#include <gtest/gtest.h>

#include "app/controller/impl/PingDialogControllerImpl.h"

#include "fakes/app/controller/FakeContentDialogController.h"
#include "fakes/app/controller/FakePingController.h"

#include "TestHost.h"

namespace tailgate::uwp::tests
{
namespace
{

namespace di = boost::di;

class Given_PingDialogController : public testing::Test
{
protected:
    void SetUp() override
    {
        m_dialog = std::make_shared<FakeContentDialogController>();
        m_ping = std::make_shared<FakePingController>();
        auto injector = di::make_injector(di::bind<ContentDialogController>.to(
                                              [this](const auto&) -> ContentDialogController&
                                              {
                                                  return *m_dialog;
                                              }),
                                          di::bind<PingController>.to(
                                              [this](const auto&) -> PingController&
                                              {
                                                  return *m_ping;
                                              }));
        m_subject = injector.create<std::unique_ptr<PingDialogControllerImpl>>();
    }

    std::shared_ptr<FakeContentDialogController> m_dialog;
    std::shared_ptr<FakePingController> m_ping;
    std::unique_ptr<PingDialogControllerImpl> m_subject;
};

TEST_F(Given_PingDialogController, When_ShowingRemoteDevice_Then_PingStarts)
{
    const winrt::hstring deviceName = L"remote-device";
    const winrt::hstring address = L"100.64.0.2";
    const winrt::hstring selfAddress = L"100.64.0.1";

    TestHost::RunOnUiThread(
        [this, &deviceName, &address, &selfAddress]
        {
            m_subject->Show(deviceName, address, selfAddress);
        });

    EXPECT_EQ(m_subject->GetState().DeviceName(), deviceName);
    EXPECT_EQ(m_subject->GetState().Error(), PingDialogError::None);
    EXPECT_EQ(m_dialog->GetState().Current(), ContentDialogControllerState::Ping);
    EXPECT_EQ(m_ping->StopCount, 1U);
    EXPECT_TRUE(m_ping->StartCall.has_value());
    EXPECT_EQ(m_ping->StartCall.value_or(PingStartCall{}).address, address);
    EXPECT_EQ(m_ping->StartCall.value_or(PingStartCall{}).selfAddress, selfAddress);
}

TEST_F(Given_PingDialogController, When_ShowingLocalDevice_Then_ValidationErrorReplacesPing)
{
    const winrt::hstring address = L"100.64.0.1";

    TestHost::RunOnUiThread(
        [this, &address]
        {
            m_subject->Show(L"local-device", address, address);
        });

    EXPECT_EQ(m_subject->GetState().Error(), PingDialogError::LocalAddress);
    EXPECT_EQ(m_subject->GetState().ErrorDetail(), address);
    EXPECT_EQ(m_dialog->GetState().Current(), ContentDialogControllerState::Ping);
    EXPECT_FALSE(m_ping->StartCall.has_value());
}

} // namespace
} // namespace tailgate::uwp::tests
