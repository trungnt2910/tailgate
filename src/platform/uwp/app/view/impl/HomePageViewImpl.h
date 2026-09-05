#pragma once

#include <memory>
#include <vector>

#include "app/controller/ClipboardController.h"
#include "app/controller/DevicePageController.h"
#include "app/controller/ExitNodeController.h"
#include "app/controller/HomePageController.h"
#include "app/controller/NavigationController.h"
#include "app/controller/PingDialogController.h"
#include "app/controller/ProfilePictureController.h"
#include "app/controller/SessionController.h"
#include "app/controller/SettingsController.h"
#include "app/model/HomePageState.h"
#include "app/model/SettingsState.h"
#include "app/ui/AppResources.h"
#include "app/view/HomePageView.h"

namespace tailgate::uwp
{

class ButtonFactory;
class ResourceLoader;
class UiFactory;

class HomePageViewImpl final : public HomePageView
{
public:
    HomePageViewImpl(AppResources& resources,
                     ResourceLoader& resourceLoader,
                     ButtonFactory& buttonFactory,
                     UiFactory& uiFactory,
                     ClipboardController& clipboardController,
                     DevicePageController& devicePageController,
                     ExitNodeController& exitNodeController,
                     HomePageController& controller,
                     NavigationController& navigationController,
                     PingDialogController& pingDialogController,
                     ProfilePictureController& profilePictureController,
                     SessionController& sessionController,
                     SettingsController& settingsController);

    [[nodiscard]] xaml::UIElement Page() const override;

private:
    struct DeviceListItem
    {
        winrt::hstring Identity;
        UwpDevice Device;
        controls::ListViewItem Item{nullptr};
    };

    struct DeviceListGroup
    {
        winrt::hstring Name;
        collections::PropertySet Source{nullptr};
        collections::IObservableVector<foundation::IInspectable> Items{nullptr};
    };

    struct Presentation
    {
        winrt::hstring Status;
        AppStyle StatusStyle = AppStyle::TextOfflineStatus;
        bool Connected = false;
        bool Busy = false;
        bool HasStoredProfile = false;
    };

    void Render() override;
    void OnStateChange(const std::string& stateName) override;
    [[nodiscard]] winrt::hstring DisplayStatus() const;
    [[nodiscard]] AppStyle StatusStyle() const;
    [[nodiscard]] xaml::UIElement BuildExitNodeCard();
    [[nodiscard]] std::shared_ptr<DeviceListItem> CreateDeviceListItem(const UwpDevice& device);
    void UpdateDeviceListItem(DeviceListItem& item, const winrt::hstring& selfAddress);
    void ReconcileDeviceItems();

    const SettingsState& m_state;
    const HomePageState& m_pageState;
    AppResources& m_resources;
    ResourceLoader& m_resourceLoader;
    ButtonFactory& m_buttonFactory;
    ClipboardController& m_clipboardController;
    DevicePageController& m_devicePageController;
    ExitNodeController& m_exitNodeController;
    HomePageController& m_controller;
    NavigationController& m_navigationController;
    PingDialogController& m_pingDialogController;
    ProfilePictureController& m_profilePictureController;
    SessionController& m_sessionController;
    UiFactory& m_uiFactory;
    Presentation m_presentation;
    controls::Grid m_page;
    controls::Grid m_body;
    controls::ToggleSwitch m_toggle;
    controls::TextBlock m_tailnetTitle;
    controls::TextBlock m_status;
    controls::Button m_account;
    xaml::UIElement m_defaultAccountContent = nullptr;
    controls::StackPanel m_disconnectedBody;
    controls::ProgressRing m_disconnectedProgress;
    controls::StackPanel m_disconnectedContent;
    controls::TextBlock m_disconnectedMessage;
    controls::TextBlock m_disconnectedDetail;
    controls::Button m_connectButton;
    controls::Grid m_connectedBody;
    controls::Grid m_exitNodeCard;
    controls::AutoSuggestBox m_search;
    controls::ListView m_deviceList;
    xaml_data::CollectionViewSource m_deviceGroups;
    collections::IObservableVector<foundation::IInspectable> m_groupedDeviceItems{nullptr};
    std::vector<std::shared_ptr<DeviceListItem>> m_deviceItems;
    std::vector<std::shared_ptr<DeviceListGroup>> m_deviceItemGroups;
    winrt::hstring m_renderedSelfAddress;
};

} // namespace tailgate::uwp
