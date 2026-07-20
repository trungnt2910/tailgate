#pragma once

#include "app/controller/SettingsController.h"
#include "app/model/SettingsState.h"
#include "app/view/SettingsPageView.h"

namespace tailgate::uwp
{

class AppResources;
class ClipboardController;
class NavigationController;
class PackageController;
class ProfilePictureController;
class ResourceLoader;
class SessionController;
class UiFactory;

class SettingsPageViewImpl final : public SettingsPageView
{
public:
    SettingsPageViewImpl(AppResources& resources,
                         ResourceLoader& resourceLoader,
                         UiFactory& uiFactory,
                         ClipboardController& clipboardController,
                         NavigationController& navigationController,
                         PackageController& packageController,
                         ProfilePictureController& profilePictureController,
                         SessionController& sessionController,
                         SettingsController& settingsController);

    [[nodiscard]] xaml::UIElement Page() const override;

private:
    void Render() override;
    void OnStateChange(const std::string& stateName) override;
    [[nodiscard]] bool SignedIn() const;

    const SettingsState& m_state;
    AppResources& m_resources;
    ResourceLoader& m_resourceLoader;
    ClipboardController& m_clipboardController;
    NavigationController& m_navigationController;
    PackageController& m_packageController;
    ProfilePictureController& m_profilePictureController;
    SessionController& m_sessionController;
    UiFactory& m_uiFactory;
    controls::ContentControl m_page;
    controls::Grid m_profilePicture;
    controls::StackPanel m_accountText;
    controls::TextBlock m_accountTitle;
    controls::TextBlock m_tailnetTitle;
    controls::TextBlock m_notSignedIn;
    controls::FontIcon m_profileChevron;
    controls::ListViewItem m_adminItem;
    controls::ListViewItem m_signedInSpacing;
    controls::ListViewItem m_serverItem;
    controls::TextBlock m_serverValue;
    controls::TextBlock m_versionText;
};

} // namespace tailgate::uwp
