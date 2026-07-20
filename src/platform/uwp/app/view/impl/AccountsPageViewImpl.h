#pragma once

#include "app/controller/SettingsController.h"
#include "app/model/SettingsState.h"
#include "app/view/AccountsPageView.h"

namespace tailgate::uwp
{

class AppResources;
class NavigationController;
class ProfilePictureController;
class ResourceLoader;
class SessionController;
class UiFactory;

class AccountsPageViewImpl final : public AccountsPageView
{
public:
    AccountsPageViewImpl(AppResources& resources,
                         ResourceLoader& resourceLoader,
                         UiFactory& uiFactory,
                         NavigationController& navigationController,
                         ProfilePictureController& profilePictureController,
                         SessionController& sessionController,
                         SettingsController& settingsController);

    [[nodiscard]] xaml::UIElement Page() const override;

private:
    void Render() override;
    void OnStateChange(const std::string& stateName) override;

    const SettingsState& m_state;
    AppResources& m_resources;
    ResourceLoader& m_resourceLoader;
    NavigationController& m_navigationController;
    ProfilePictureController& m_profilePictureController;
    SessionController& m_sessionController;
    UiFactory& m_uiFactory;
    controls::ContentControl m_page;
    controls::Grid m_profilePicture;
    controls::TextBlock m_accountTitle;
    controls::TextBlock m_tailnetTitle;
};

} // namespace tailgate::uwp
