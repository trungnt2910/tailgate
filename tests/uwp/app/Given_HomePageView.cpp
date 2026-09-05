#include <memory>
#include <string_view>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "app/view/impl/HomePageViewImpl.h"

#include "fakes/app/controller/FakeClipboardController.h"
#include "fakes/app/controller/FakeDevicePageController.h"
#include "fakes/app/controller/FakeExitNodeController.h"
#include "fakes/app/controller/FakeHomePageController.h"
#include "fakes/app/controller/FakeNavigationController.h"
#include "fakes/app/controller/FakePingDialogController.h"
#include "fakes/app/controller/FakeProfilePictureController.h"
#include "fakes/app/controller/FakeSessionController.h"
#include "fakes/app/controller/FakeSettingsController.h"

#include "TestHost.h"
#include "ViewTestInjector.h"

namespace tailgate::uwp::tests
{
namespace
{

template <typename Type>
Type FindDescendant(const xaml::DependencyObject& root)
{
    if (const auto result = root.try_as<Type>())
    {
        return result;
    }
    const std::int32_t count = media::VisualTreeHelper::GetChildrenCount(root);
    for (std::int32_t index = 0; index < count; ++index)
    {
        if (const auto result =
                FindDescendant<Type>(media::VisualTreeHelper::GetChild(root, index)))
        {
            return result;
        }
    }
    return nullptr;
}

bool ContainsText(const xaml::DependencyObject& root, std::wstring_view text)
{
    if (const auto block = root.try_as<controls::TextBlock>(); block && block.Text() == text)
    {
        return true;
    }
    const std::int32_t count = media::VisualTreeHelper::GetChildrenCount(root);
    for (std::int32_t index = 0; index < count; ++index)
    {
        if (ContainsText(media::VisualTreeHelper::GetChild(root, index), text))
        {
            return true;
        }
    }
    return false;
}

std::pair<controls::ListViewItem, std::uint32_t> FindDeviceItem(const controls::ListView& list,
                                                                std::wstring_view address)
{
    for (std::uint32_t index = 0; index < list.Items().Size(); ++index)
    {
        const auto item = list.Items().GetAt(index).try_as<controls::ListViewItem>();
        const auto content = item ? item.Content().try_as<xaml::DependencyObject>() : nullptr;
        if (content && ContainsText(content, address))
        {
            return {item, index};
        }
    }
    return {nullptr, 0};
}

class Given_HomePageView : public testing::Test
{
protected:
    [[nodiscard]] static std::vector<UwpDevice> Devices()
    {
        return {
            UwpDevice(1,
                      L"Example User",
                      L"local.example.ts.net",
                      L"100.64.0.1",
                      {},
                      L"Windows",
                      true,
                      false),
            UwpDevice(2,
                      L"Example User",
                      L"peer.example.ts.net",
                      L"100.64.0.2",
                      {},
                      L"Linux",
                      true,
                      true),
            UwpDevice(3,
                      L"Example User",
                      L"offline.example.ts.net",
                      L"100.64.0.3",
                      {},
                      L"Linux",
                      false,
                      false),
        };
    }

    xaml::UIElement CreateSubject()
    {
        m_dependencies.Initialize();
        m_clipboard = std::make_shared<FakeClipboardController>();
        m_devicePage = std::make_shared<FakeDevicePageController>();
        m_exitNode = std::make_shared<FakeExitNodeController>();
        m_home = std::make_shared<FakeHomePageController>();
        m_navigation = std::make_shared<FakeNavigationController>();
        m_pingDialog = std::make_shared<FakePingDialogController>();
        m_profilePicture = std::make_shared<FakeProfilePictureController>();
        m_session = std::make_shared<FakeSessionController>();
        m_settings = std::make_shared<FakeSettingsController>();
        m_settings->GetState().TailnetDisplayName(L"Example Tailnet");
        m_settings->GetState().AccountDisplayName(L"Example User");
        m_settings->GetState().HasStoredProfile(true);
        m_settings->GetState().SelfAddress(L"100.64.0.1");
        m_settings->GetState().Devices(Devices());
        m_session->GetState().Connected(true);
        m_exitNode->GetState().Current(L"peer.example.ts.net");
        m_exitNode->GetState().Selection(L"peer.example.ts.net");
        m_subject = m_dependencies.Create<HomePageViewImpl>(
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
            di::bind<ExitNodeController>.to(
                [this](const auto&) -> ExitNodeController&
                {
                    return *m_exitNode;
                }),
            di::bind<HomePageController>.to(
                [this](const auto&) -> HomePageController&
                {
                    return *m_home;
                }),
            di::bind<NavigationController>.to(
                [this](const auto&) -> NavigationController&
                {
                    return *m_navigation;
                }),
            di::bind<PingDialogController>.to(
                [this](const auto&) -> PingDialogController&
                {
                    return *m_pingDialog;
                }),
            di::bind<ProfilePictureController>.to(
                [this](const auto&) -> ProfilePictureController&
                {
                    return *m_profilePicture;
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
        return m_subject->Page();
    }

    ViewTestInjector m_dependencies;
    std::shared_ptr<FakeClipboardController> m_clipboard;
    std::shared_ptr<FakeDevicePageController> m_devicePage;
    std::shared_ptr<FakeExitNodeController> m_exitNode;
    std::shared_ptr<FakeHomePageController> m_home;
    std::shared_ptr<FakeNavigationController> m_navigation;
    std::shared_ptr<FakePingDialogController> m_pingDialog;
    std::shared_ptr<FakeProfilePictureController> m_profilePicture;
    std::shared_ptr<FakeSessionController> m_session;
    std::shared_ptr<FakeSettingsController> m_settings;
    std::unique_ptr<HomePageViewImpl> m_subject;
};

TEST_F(Given_HomePageView, When_Connected_Then_HomePageMatchesGolden)
{
    TestHost::SetTestContentAsync(
        [this]() -> xaml::UIElement
        {
            return CreateSubject();
        })
        .get();

    const auto result =
        TestHost::CheckGolden(L"Given_HomePageView/When_Connected_Then_HomePageMatchesGolden.png");

    EXPECT_TRUE(result);
}

TEST_F(Given_HomePageView, When_SignedOut_Then_HomePageMatchesGolden)
{
    TestHost::SetTestContentAsync(
        [this]() -> xaml::UIElement
        {
            return CreateSubject();
        })
        .get();

    TestHost::RunOnUiThread(
        [this]
        {
            m_session->GetState().Connected(false);
            m_settings->GetState().HasStoredProfile(false);
        });
    TestHost::WaitForIdleAsync().get();
    const auto result =
        TestHost::CheckGolden(L"Given_HomePageView/When_SignedOut_Then_HomePageMatchesGolden.png");

    EXPECT_TRUE(result);
}

TEST_F(Given_HomePageView, When_DeviceChanges_Then_ListItemIsUpdatedInPlace)
{
    const xaml::UIElement page = TestHost::SetTestContentAsync(
                                     [this]() -> xaml::UIElement
                                     {
                                         return CreateSubject();
                                     })
                                     .get();
    controls::ListView list{nullptr};
    controls::ListViewItem itemBefore{nullptr};
    foundation::IInspectable sourceBefore{nullptr};
    TestHost::RunOnUiThread(
        [&]
        {
            list = FindDescendant<controls::ListView>(page);
            if (list)
            {
                sourceBefore = list.ItemsSource();
                itemBefore = FindDeviceItem(list, L"100.64.0.2").first;
            }
        });
    ASSERT_TRUE(list);
    ASSERT_TRUE(itemBefore);
    ASSERT_TRUE(sourceBefore);

    TestHost::RunOnUiThread(
        [this]
        {
            std::vector<UwpDevice> devices = Devices();
            devices[1] = UwpDevice(2,
                                   L"Shared Devices",
                                   L"renamed.example.ts.net",
                                   L"100.64.0.22",
                                   {},
                                   L"Windows",
                                   false,
                                   true);
            m_settings->GetState().Devices(std::move(devices));
        });

    controls::ListViewItem itemAfter{nullptr};
    foundation::IInspectable sourceAfter{nullptr};
    bool hasUpdatedName = false;
    TestHost::RunOnUiThread(
        [&]
        {
            itemAfter = FindDeviceItem(list, L"100.64.0.22").first;
            sourceAfter = list.ItemsSource();
            hasUpdatedName =
                itemAfter &&
                ContainsText(itemAfter.Content().as<xaml::DependencyObject>(), L"renamed");
        });
    EXPECT_EQ(sourceAfter, sourceBefore);
    EXPECT_EQ(itemAfter, itemBefore);
    EXPECT_TRUE(hasUpdatedName);
}

TEST_F(Given_HomePageView, When_DeviceOrderChanges_Then_ListItemIsMovedWithoutReplacement)
{
    const xaml::UIElement page = TestHost::SetTestContentAsync(
                                     [this]() -> xaml::UIElement
                                     {
                                         return CreateSubject();
                                     })
                                     .get();
    controls::ListView list{nullptr};
    controls::ListViewItem itemBefore{nullptr};
    std::uint32_t indexBefore = 0;
    TestHost::RunOnUiThread(
        [&]
        {
            list = FindDescendant<controls::ListView>(page);
            if (list)
            {
                const auto found = FindDeviceItem(list, L"100.64.0.2");
                itemBefore = found.first;
                indexBefore = found.second;
            }
        });
    ASSERT_TRUE(list);
    ASSERT_TRUE(itemBefore);

    TestHost::RunOnUiThread(
        [this]
        {
            std::vector<UwpDevice> devices = Devices();
            std::swap(devices[1], devices[2]);
            m_settings->GetState().Devices(std::move(devices));
        });

    controls::ListViewItem itemAfter{nullptr};
    std::uint32_t indexAfter = 0;
    TestHost::RunOnUiThread(
        [&]
        {
            const auto found = FindDeviceItem(list, L"100.64.0.2");
            itemAfter = found.first;
            indexAfter = found.second;
        });
    EXPECT_EQ(itemAfter, itemBefore);
    EXPECT_EQ(indexBefore, 1U);
    EXPECT_EQ(indexAfter, 2U);
}

TEST_F(Given_HomePageView, When_UnrelatedStateChanges_Then_ItemsSourceAndItemsRemainStable)
{
    const xaml::UIElement page = TestHost::SetTestContentAsync(
                                     [this]() -> xaml::UIElement
                                     {
                                         return CreateSubject();
                                     })
                                     .get();
    controls::ListView list{nullptr};
    controls::ListViewItem itemBefore{nullptr};
    foundation::IInspectable sourceBefore{nullptr};
    TestHost::RunOnUiThread(
        [&]
        {
            list = FindDescendant<controls::ListView>(page);
            if (list)
            {
                sourceBefore = list.ItemsSource();
                itemBefore = FindDeviceItem(list, L"100.64.0.2").first;
            }
        });
    ASSERT_TRUE(list);
    ASSERT_TRUE(itemBefore);
    ASSERT_TRUE(sourceBefore);

    TestHost::RunOnUiThread(
        [this]
        {
            m_settings->GetState().Update(
                [](SettingsState&)
                {
                });
        });

    controls::ListViewItem itemAfter{nullptr};
    foundation::IInspectable sourceAfter{nullptr};
    TestHost::RunOnUiThread(
        [&]
        {
            itemAfter = FindDeviceItem(list, L"100.64.0.2").first;
            sourceAfter = list.ItemsSource();
        });
    EXPECT_EQ(sourceAfter, sourceBefore);
    EXPECT_EQ(itemAfter, itemBefore);
}

} // namespace
} // namespace tailgate::uwp::tests
