#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "app/view/impl/DevicePageViewImpl.h"

#include "fakes/app/controller/FakeClipboardController.h"
#include "fakes/app/controller/FakeDevicePageController.h"
#include "fakes/app/controller/FakePingDialogController.h"
#include "fakes/app/controller/FakeSettingsController.h"

#include "TestHost.h"
#include "ViewTestInjector.h"

namespace tailgate::uwp::tests
{
namespace
{

class Given_DevicePageView : public testing::Test
{
protected:
    xaml::UIElement CreateSubject()
    {
        m_dependencies.Initialize();
        m_clipboard = std::make_shared<FakeClipboardController>();
        m_devicePage = std::make_shared<FakeDevicePageController>();
        m_pingDialog = std::make_shared<FakePingDialogController>();
        m_settings = std::make_shared<FakeSettingsController>();
        m_devicePage->GetState().SelectedDeviceId(L"peer.example.ts.net");
        m_settings->GetState().SelfAddress(L"100.64.0.1");
        m_settings->GetState().Devices(std::vector<UwpDevice>{
            UwpDevice{.Group = L"Example User",
                      .Name = L"peer.example.ts.net",
                      .Address = L"100.64.0.2",
                      .Ipv6 = L"fd7a:115c:a1e0::2",
                      .OperatingSystem = L"Linux",
                      .Online = true,
                      .ExitNodeOption = false},
        });
        m_subject = m_dependencies.Create<DevicePageViewImpl>(
            di::bind<ClipboardController>.to(
                [this](const auto&) -> ClipboardController&
                {
                    return *m_clipboard;
                }),
            di::bind<DevicePageController>.to(
                [this](const auto&) -> DevicePageController&
                {
                    return *m_devicePage;
                }),
            di::bind<PingDialogController>.to(
                [this](const auto&) -> PingDialogController&
                {
                    return *m_pingDialog;
                }),
            di::bind<SettingsController>.to(
                [this](const auto&) -> SettingsController&
                {
                    return *m_settings;
                }));
        return m_subject->Page();
    }

    ViewTestInjector m_dependencies;
    std::shared_ptr<FakeClipboardController> m_clipboard;
    std::shared_ptr<FakeDevicePageController> m_devicePage;
    std::shared_ptr<FakePingDialogController> m_pingDialog;
    std::shared_ptr<FakeSettingsController> m_settings;
    std::unique_ptr<DevicePageViewImpl> m_subject;
};

TEST_F(Given_DevicePageView, When_DeviceIsAvailable_Then_DevicePageMatchesGolden)
{
    TestHost::SetTestContentAsync(
        [this]() -> xaml::UIElement
        {
            return CreateSubject();
        })
        .get();

    const auto result = TestHost::CheckGolden(
        L"Given_DevicePageView/When_DeviceIsAvailable_Then_DevicePageMatchesGolden.png");

    EXPECT_TRUE(result);
}

} // namespace
} // namespace tailgate::uwp::tests
