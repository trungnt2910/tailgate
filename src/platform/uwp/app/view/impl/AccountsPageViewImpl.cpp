#include "app/view/impl/AccountsPageViewImpl.h"

#include <utility>

#include <winrt/Windows.UI.Xaml.Input.h>

#include "common/ResourceLoader.h"
#include "strings/Resources.h"

#include "app/controller/NavigationController.h"
#include "app/controller/ProfilePictureController.h"
#include "app/controller/SessionController.h"
#include "app/ui/AppResources.h"
#include "app/ui/UiFactory.h"

namespace tailgate::uwp
{

AccountsPageViewImpl::AccountsPageViewImpl(AppResources& resources,
                                           ResourceLoader& resourceLoader,
                                           UiFactory& uiFactory,
                                           NavigationController& navigationController,
                                           ProfilePictureController& profilePictureController,
                                           SessionController& sessionController,
                                           SettingsController& settingsController)
    : m_state(settingsController.GetState()),
      m_resources(resources),
      m_resourceLoader(resourceLoader),
      m_navigationController(navigationController),
      m_profilePictureController(profilePictureController),
      m_sessionController(sessionController),
      m_uiFactory(uiFactory)
{
    Subscribe(m_state, "settings");
    Subscribe(m_profilePictureController.GetState(), "profile-picture");
    Subscribe(m_sessionController.GetState(), "session");
    Initialize();
}

void AccountsPageViewImpl::Render()
{
    m_page.HorizontalContentAlignment(xaml::HorizontalAlignment::Stretch);
    m_page.VerticalContentAlignment(xaml::VerticalAlignment::Stretch);
    controls::ListView list = m_uiFactory.PageListView();

    controls::StackPanel profileRow;
    profileRow.Orientation(controls::Orientation::Horizontal);
    m_profilePicture.VerticalAlignment(xaml::VerticalAlignment::Center);
    profileRow.Children().Append(m_profilePicture);
    controls::StackPanel accountText;
    accountText.Margin(m_resources.Thickness(AppThickness::AccountTextMargin));
    accountText.VerticalAlignment(xaml::VerticalAlignment::Center);
    m_accountTitle = m_uiFactory.Text(L"", AppStyle::TextBodyStrong);
    accountText.Children().Append(m_accountTitle);
    m_tailnetTitle = m_uiFactory.Text(L"", AppStyle::TextSecondarySmall);
    accountText.Children().Append(m_tailnetTitle);
    profileRow.Children().Append(accountText);
    list.Items().Append(m_uiFactory.ListItem(profileRow));

    list.Items().Append(m_uiFactory.SectionSpacing());

    auto logoutText = m_uiFactory.Text(m_resourceLoader.Get(Resources::Accounts::LogOut),
                                       AppStyle::TextErrorBody);
    auto logoutItem = m_uiFactory.ListItem(logoutText);
    logoutItem.Tapped(
        [this](const auto&, const auto&)
        {
            m_navigationController.Home();
            m_sessionController.Logout();
        });
    list.Items().Append(logoutItem);
    m_page.Content(
        m_uiFactory.PageChrome(m_resourceLoader.Get(Resources::Accounts::PageTitle), list));
}

void AccountsPageViewImpl::OnStateChange(const std::string&)
{
    m_profilePicture.Children().Clear();
    m_profilePicture.Children().Append(
        m_uiFactory.ProfilePicture(m_resources.Double(AppDouble::ProfilePictureSize),
                                   m_profilePictureController.GetState().Image()));
    const winrt::hstring accountTitle = m_state.AccountTitle();
    const winrt::hstring tailnetTitle = m_state.TailnetTitle();
    m_accountTitle.Text(accountTitle.empty()
                            ? m_resourceLoader.Get(Resources::Settings::NotSignedIn)
                            : accountTitle);
    m_tailnetTitle.Text(tailnetTitle.empty() ? m_resourceLoader.Get(Resources::Brand::ProductName)
                                             : tailnetTitle);
}

xaml::UIElement AccountsPageViewImpl::Page() const
{
    return m_page;
}

} // namespace tailgate::uwp
