#pragma once

#include <memory>

#include "app/view/NavigationPageView.h"

namespace tailgate::uwp
{

class AccountsPageView;
class DevicePageView;
class ExitNodeControlView;
class HomePageView;
class NavigationController;
class SettingsPageView;

class NavigationPageViewImpl final : public NavigationPageView
{
public:
    NavigationPageViewImpl(NavigationController& navigationController,
                           std::unique_ptr<AccountsPageView> accountsPage,
                           std::unique_ptr<DevicePageView> devicePage,
                           std::unique_ptr<ExitNodeControlView> exitNodePage,
                           std::unique_ptr<HomePageView> homePage,
                           std::unique_ptr<SettingsPageView> settingsPage);

    [[nodiscard]] xaml::UIElement Page() const override;

private:
    void Render() override;
    void OnStateChange(const std::string& stateName) override;

    NavigationController& m_navigationController;
    std::unique_ptr<AccountsPageView> m_accountsPage;
    std::unique_ptr<DevicePageView> m_devicePage;
    std::unique_ptr<ExitNodeControlView> m_exitNodePage;
    std::unique_ptr<HomePageView> m_homePage;
    std::unique_ptr<SettingsPageView> m_settingsPage;
    controls::ContentControl m_page;
};

} // namespace tailgate::uwp
