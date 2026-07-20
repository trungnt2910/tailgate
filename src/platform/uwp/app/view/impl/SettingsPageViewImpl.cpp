#include "app/view/impl/SettingsPageViewImpl.h"

#include <utility>

#include <winrt/Windows.System.h>
#include <winrt/Windows.UI.Xaml.Documents.h>
#include <winrt/Windows.UI.Xaml.Input.h>

#include "common/ResourceLoader.h"
#include "common/VpnConstants.h"
#include "strings/Resources.h"

#include "app/controller/ClipboardController.h"
#include "app/controller/NavigationController.h"
#include "app/controller/PackageController.h"
#include "app/controller/ProfilePictureController.h"
#include "app/controller/SessionController.h"
#include "app/ui/AppResources.h"
#include "app/ui/Glyphs.h"
#include "app/ui/UiFactory.h"

namespace tailgate::uwp
{

namespace documents = winrt::Windows::UI::Xaml::Documents;
namespace winsystem = winrt::Windows::System;

SettingsPageViewImpl::SettingsPageViewImpl(AppResources& resources,
                                           ResourceLoader& resourceLoader,
                                           UiFactory& uiFactory,
                                           ClipboardController& clipboardController,
                                           NavigationController& navigationController,
                                           PackageController& packageController,
                                           ProfilePictureController& profilePictureController,
                                           SessionController& sessionController,
                                           SettingsController& settingsController)
    : m_state(settingsController.GetState()),
      m_resources(resources),
      m_resourceLoader(resourceLoader),
      m_clipboardController(clipboardController),
      m_navigationController(navigationController),
      m_packageController(packageController),
      m_profilePictureController(profilePictureController),
      m_sessionController(sessionController),
      m_uiFactory(uiFactory)
{
    Subscribe(m_state, "settings");
    Subscribe(m_profilePictureController.GetState(), "profile-picture");
    Subscribe(m_sessionController.GetState(), "session");
    Initialize();
}

void SettingsPageViewImpl::Render()
{
    m_page.HorizontalContentAlignment(xaml::HorizontalAlignment::Stretch);
    m_page.VerticalContentAlignment(xaml::VerticalAlignment::Stretch);
    controls::ListView list = m_uiFactory.PageListView();

    controls::Grid profileRow;
    auto pictureColumn = controls::ColumnDefinition();
    pictureColumn.Width(xaml::GridLengthHelper::Auto());
    profileRow.ColumnDefinitions().Append(pictureColumn);
    auto textColumn = controls::ColumnDefinition();
    textColumn.Width(xaml::GridLengthHelper::FromValueAndType(1, xaml::GridUnitType::Star));
    profileRow.ColumnDefinitions().Append(textColumn);
    auto chevronColumn = controls::ColumnDefinition();
    chevronColumn.Width(xaml::GridLengthHelper::Auto());
    profileRow.ColumnDefinitions().Append(chevronColumn);
    m_profilePicture.VerticalAlignment(xaml::VerticalAlignment::Center);
    profileRow.Children().Append(m_profilePicture);
    m_accountText.Margin(m_resources.Thickness(AppThickness::AccountTextMargin));
    m_accountText.VerticalAlignment(xaml::VerticalAlignment::Center);
    m_accountTitle = m_uiFactory.Text(L"", AppStyle::TextBodyStrong);
    m_accountText.Children().Append(m_accountTitle);
    m_tailnetTitle = m_uiFactory.Text(L"", AppStyle::TextSecondarySmall);
    m_accountText.Children().Append(m_tailnetTitle);
    controls::Grid::SetColumn(m_accountText, 1);
    profileRow.Children().Append(m_accountText);
    m_notSignedIn = m_uiFactory.Text(m_resourceLoader.Get(Resources::Settings::NotSignedIn),
                                     AppStyle::TextBodyStrong);
    m_notSignedIn.VerticalAlignment(xaml::VerticalAlignment::Center);
    controls::Grid::SetColumn(m_notSignedIn, 1);
    profileRow.Children().Append(m_notSignedIn);
    m_profileChevron = m_uiFactory.FluentIcon(Glyphs::ChevronRight);
    m_profileChevron.VerticalAlignment(xaml::VerticalAlignment::Center);
    controls::Grid::SetColumn(m_profileChevron, 2);
    profileRow.Children().Append(m_profileChevron);
    auto profileItem = m_uiFactory.ListItem(profileRow);
    profileItem.Tapped(
        [this](const auto&, const auto&)
        {
            if (SignedIn())
            {
                m_navigationController.OpenPage(NavigationControllerState::Accounts);
            }
            else
            {
                m_sessionController.ConnectStoredOrRequestSignIn();
            }
        });
    list.Items().Append(profileItem);

    controls::TextBlock adminText;
    adminText.Style(m_resources.Style(AppStyle::TextBody));
    adminText.TextWrapping(xaml::TextWrapping::Wrap);
    documents::Hyperlink adminLink;
    adminLink.NavigateUri(foundation::Uri(VpnConstants::Product::AdminConsoleUrl));
    documents::Run adminLinkText;
    adminLinkText.Text(m_resourceLoader.Get(Resources::Settings::AdminConsoleDescription));
    adminLink.Inlines().Append(adminLinkText);
    adminText.Inlines().Append(adminLink);
    m_adminItem = m_uiFactory.ListItem(adminText);
    m_adminItem.Tapped(
        [](const auto&, const auto&)
        {
            (void)winsystem::Launcher::LaunchUriAsync(
                foundation::Uri(VpnConstants::Product::AdminConsoleUrl));
        });
    list.Items().Append(m_adminItem);
    m_signedInSpacing = m_uiFactory.SectionSpacing();
    list.Items().Append(m_signedInSpacing);

    controls::Grid serverRow;
    auto serverTextColumn = controls::ColumnDefinition();
    serverTextColumn.Width(xaml::GridLengthHelper::FromValueAndType(1, xaml::GridUnitType::Star));
    serverRow.ColumnDefinitions().Append(serverTextColumn);
    auto serverIconColumn = controls::ColumnDefinition();
    serverIconColumn.Width(xaml::GridLengthHelper::Auto());
    serverRow.ColumnDefinitions().Append(serverIconColumn);
    controls::StackPanel serverText;
    serverText.Children().Append(
        m_uiFactory.Text(m_resourceLoader.Get(Resources::Settings::Server), AppStyle::TextBody));
    m_serverValue = m_uiFactory.Text(L"", AppStyle::TextSecondaryCaption);
    serverText.Children().Append(m_serverValue);
    serverRow.Children().Append(serverText);
    auto copyIcon = m_uiFactory.FluentIcon(Glyphs::Copy);
    copyIcon.VerticalAlignment(xaml::VerticalAlignment::Center);
    copyIcon.Margin(m_resources.Thickness(AppThickness::AccountTextMargin));
    controls::Grid::SetColumn(copyIcon, 1);
    serverRow.Children().Append(copyIcon);
    m_serverItem = m_uiFactory.ListItem(serverRow);
    m_serverItem.Tapped(
        [this](const auto&, const auto&)
        {
            const winrt::hstring hostPort =
                m_state.TailgateServer().empty()
                    ? m_resourceLoader.Get(Resources::Settings::NotConfigured)
                    : m_state.TailgateHostPort();
            m_clipboardController.SetText(hostPort);
        });
    list.Items().Append(m_serverItem);

    list.Items().Append(m_uiFactory.SectionSpacing());
    auto bugItem = m_uiFactory.ListItem(
        m_uiFactory.Text(m_resourceLoader.Get(Resources::Settings::BugReport), AppStyle::TextBody));
    bugItem.Tapped(
        [](const auto&, const auto&)
        {
            (void)winsystem::Launcher::LaunchUriAsync(
                foundation::Uri(VpnConstants::Product::BugReportUrl));
        });
    list.Items().Append(bugItem);
    controls::StackPanel aboutText;
    aboutText.Children().Append(
        m_uiFactory.Text(m_resourceLoader.Get(Resources::Settings::About), AppStyle::TextBody));
    m_versionText = m_uiFactory.Text(L"", AppStyle::TextSecondaryCaption);
    aboutText.Children().Append(m_versionText);
    list.Items().Append(m_uiFactory.ListItem(aboutText));
    m_page.Content(
        m_uiFactory.PageChrome(m_resourceLoader.Get(Resources::Settings::PageTitle), list));
}

void SettingsPageViewImpl::OnStateChange(const std::string&)
{
    const bool signedIn = SignedIn();
    const xaml::Visibility signedInVisibility =
        signedIn ? xaml::Visibility::Visible : xaml::Visibility::Collapsed;
    const xaml::Visibility signedOutVisibility =
        signedIn ? xaml::Visibility::Collapsed : xaml::Visibility::Visible;

    m_profilePicture.Children().Clear();
    if (signedIn)
    {
        m_profilePicture.Children().Append(
            m_uiFactory.ProfilePicture(m_resources.Double(AppDouble::ProfilePictureSize),
                                       m_profilePictureController.GetState().Image()));
    }
    m_accountText.Visibility(signedInVisibility);
    const winrt::hstring accountTitle = m_state.AccountTitle();
    const winrt::hstring tailnetTitle = m_state.TailnetTitle();
    m_accountTitle.Text(accountTitle.empty()
                            ? m_resourceLoader.Get(Resources::Settings::NotSignedIn)
                            : accountTitle);
    m_tailnetTitle.Text(tailnetTitle.empty() ? m_resourceLoader.Get(Resources::Brand::ProductName)
                                             : tailnetTitle);
    m_notSignedIn.Visibility(signedOutVisibility);
    m_profileChevron.Visibility(signedInVisibility);
    m_adminItem.Visibility(signedInVisibility);
    m_signedInSpacing.Visibility(signedInVisibility);
    m_serverItem.Visibility(signedInVisibility);
    m_serverValue.Text(m_state.TailgateServer().empty()
                           ? m_resourceLoader.Get(Resources::Settings::NotConfigured)
                           : m_state.TailgateHostPort());
    m_versionText.Text(
        m_resourceLoader.Format(Resources::Settings::Version,
                                std::wstring_view(m_packageController.GetState().VersionText())));
}

bool SettingsPageViewImpl::SignedIn() const
{
    return m_state.HasStoredProfile() || m_sessionController.GetState().Connected() ||
           !m_state.AccountName().empty();
}

xaml::UIElement SettingsPageViewImpl::Page() const
{
    return m_page;
}

} // namespace tailgate::uwp
