#pragma once

#include "app/view/DevicePageView.h"

namespace tailgate::uwp
{

class AppResources;
class ButtonFactory;
class ClipboardController;
class DevicePageController;
class PingDialogController;
class ResourceLoader;
class SettingsController;
class UiFactory;
struct UwpDevice;

class DevicePageViewImpl final : public DevicePageView
{
public:
    DevicePageViewImpl(AppResources& resources,
                       ResourceLoader& resourceLoader,
                       ButtonFactory& buttonFactory,
                       UiFactory& uiFactory,
                       ClipboardController& clipboardController,
                       DevicePageController& devicePageController,
                       PingDialogController& pingDialogController,
                       SettingsController& settingsController);

    [[nodiscard]] xaml::UIElement Page() const override;

private:
    void Render() override;
    void OnStateChange(const std::string& stateName) override;
    [[nodiscard]] const UwpDevice* SelectedDevice() const;

    AppResources& m_resources;
    ResourceLoader& m_resourceLoader;
    ButtonFactory& m_buttonFactory;
    UiFactory& m_uiFactory;
    ClipboardController& m_clipboardController;
    DevicePageController& m_devicePageController;
    PingDialogController& m_pingDialogController;
    SettingsController& m_settingsController;
    controls::ContentControl m_page;
    controls::TextBlock m_deviceName;
    controls::Grid m_statusDot;
    controls::TextBlock m_status;
    controls::Button m_pingButton;
    controls::ListView m_details;
};

} // namespace tailgate::uwp
