#include "app/view/impl/NavigationPageViewImpl.h"

#include <utility>

#include "app/controller/NavigationController.h"
#include "app/model/NavigationState.h"
#include "app/view/AccountsPageView.h"
#include "app/view/DevicePageView.h"
#include "app/view/ExitNodeControlView.h"
#include "app/view/HomePageView.h"
#include "app/view/SettingsPageView.h"

namespace tailgate::uwp
{

NavigationPageViewImpl::NavigationPageViewImpl(NavigationController& navigationController,
                                               std::unique_ptr<AccountsPageView> accountsPage,
                                               std::unique_ptr<DevicePageView> devicePage,
                                               std::unique_ptr<ExitNodeControlView> exitNodePage,
                                               std::unique_ptr<HomePageView> homePage,
                                               std::unique_ptr<SettingsPageView> settingsPage)
    : m_navigationController(navigationController),
      m_accountsPage(std::move(accountsPage)),
      m_devicePage(std::move(devicePage)),
      m_exitNodePage(std::move(exitNodePage)),
      m_homePage(std::move(homePage)),
      m_settingsPage(std::move(settingsPage))
{
    Subscribe(m_navigationController.GetState(), "navigation");
    Initialize();
}

void NavigationPageViewImpl::Render()
{
    m_page.HorizontalContentAlignment(xaml::HorizontalAlignment::Stretch);
    m_page.VerticalContentAlignment(xaml::VerticalAlignment::Stretch);
}

void NavigationPageViewImpl::OnStateChange(const std::string&)
{
    switch (m_navigationController.GetState().Current())
    {
    case NavigationControllerState::Home:
        m_page.Content(m_homePage->Page());
        break;
    case NavigationControllerState::Settings:
        m_page.Content(m_settingsPage->Page());
        break;
    case NavigationControllerState::Accounts:
        m_page.Content(m_accountsPage->Page());
        break;
    case NavigationControllerState::Device:
        m_page.Content(m_devicePage->Page());
        break;
    case NavigationControllerState::ExitNodes:
        m_page.Content(m_exitNodePage->Page());
        break;
    }
}

xaml::UIElement NavigationPageViewImpl::Page() const
{
    return m_page;
}

} // namespace tailgate::uwp
