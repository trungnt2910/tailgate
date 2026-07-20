#include "app/view/impl/HomePageViewImpl.h"

#include <algorithm>
#include <string_view>
#include <utility>
#include <vector>

#include <winrt/Windows.UI.Xaml.Documents.h>
#include <winrt/Windows.UI.Xaml.Input.h>

#include <boost/algorithm/string/predicate.hpp>

#include "common/ResourceLoader.h"
#include "strings/Resources.h"

#include "app/ui/ButtonFactory.h"
#include "app/ui/Glyphs.h"
#include "app/ui/UiFactory.h"

namespace tailgate::uwp
{

namespace documents = winrt::Windows::UI::Xaml::Documents;

namespace
{

winrt::hstring TailnetTitle(const SettingsState& state, ResourceLoader& resourceLoader)
{
    const winrt::hstring title = state.TailnetTitle();
    return title.empty() ? resourceLoader.Get(Resources::Brand::ProductName) : title;
}

} // namespace

HomePageViewImpl::HomePageViewImpl(AppResources& resources,
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
                                   SettingsController& settingsController)
    : m_state(settingsController.GetState()),
      m_pageState(controller.GetState()),
      m_resources(resources),
      m_resourceLoader(resourceLoader),
      m_buttonFactory(buttonFactory),
      m_clipboardController(clipboardController),
      m_devicePageController(devicePageController),
      m_exitNodeController(exitNodeController),
      m_controller(controller),
      m_navigationController(navigationController),
      m_pingDialogController(pingDialogController),
      m_profilePictureController(profilePictureController),
      m_sessionController(sessionController),
      m_uiFactory(uiFactory)
{
    Subscribe(m_state, "settings");
    Subscribe(m_profilePictureController.GetState(), "profile-picture");
    Subscribe(m_sessionController.GetState(), "session");
    Initialize();
}

void HomePageViewImpl::Render()
{
    m_page.Style(m_resources.Style(AppStyle::Page));
    m_page.HorizontalAlignment(xaml::HorizontalAlignment::Stretch);

    auto headerRow = controls::RowDefinition();
    headerRow.Height(xaml::GridLengthHelper::Auto());
    m_page.RowDefinitions().Append(headerRow);
    auto bodyRow = controls::RowDefinition();
    bodyRow.Height(xaml::GridLengthHelper::FromValueAndType(1, xaml::GridUnitType::Star));
    m_page.RowDefinitions().Append(bodyRow);

    controls::Grid header;
    auto leftColumn = controls::ColumnDefinition();
    leftColumn.Width(xaml::GridLengthHelper::FromValueAndType(1, xaml::GridUnitType::Star));
    header.ColumnDefinitions().Append(leftColumn);
    auto rightColumn = controls::ColumnDefinition();
    rightColumn.Width(xaml::GridLengthHelper::Auto());
    header.ColumnDefinitions().Append(rightColumn);

    controls::StackPanel left;
    left.Orientation(controls::Orientation::Horizontal);
    m_toggle.Width(m_resources.Double(AppDouble::ToggleWidth));
    m_toggle.MinWidth(m_resources.Double(AppDouble::ToggleWidth));
    m_toggle.OnContent(foundation::PropertyValue::CreateString(L""));
    m_toggle.OffContent(foundation::PropertyValue::CreateString(L""));
    m_toggle.Margin(m_resources.Thickness(AppThickness::HeaderToggleMargin));
    m_toggle.Toggled(
        [this](const foundation::IInspectable& sender, const auto&)
        {
            const auto toggle = sender.as<controls::ToggleSwitch>();
            const bool connected = m_sessionController.GetState().Connected();
            const bool requestedConnected = toggle.IsOn();
            if (requestedConnected == connected)
            {
                return;
            }
            // The switch represents the last confirmed VPN state. Restore it immediately while
            // the asynchronous profile operation is in flight; a successful state refresh will
            // move it after Windows reports the new state.
            toggle.IsOn(connected);
            if (requestedConnected)
            {
                m_sessionController.ConnectStoredOrRequestSignIn();
            }
            else
            {
                m_sessionController.Disconnect();
            }
        });
    left.Children().Append(m_toggle);

    controls::StackPanel title;
    m_tailnetTitle = m_uiFactory.Text(L"", AppStyle::TextTitle);
    title.Children().Append(m_tailnetTitle);
    m_status = m_uiFactory.Text(L"", AppStyle::TextOfflineStatus);
    title.Children().Append(m_status);
    left.Children().Append(title);
    header.Children().Append(left);

    m_account = m_buttonFactory.CircleIcon(
        Glyphs::Person, m_resourceLoader.Get(Resources::Home::AccountAutomationName));
    m_defaultAccountContent = m_account.Content().as<xaml::UIElement>();
    m_account.HorizontalAlignment(xaml::HorizontalAlignment::Right);
    m_account.VerticalAlignment(xaml::VerticalAlignment::Top);
    m_account.Click(
        [this](const auto&, const auto&)
        {
            m_navigationController.OpenPage(NavigationControllerState::Settings);
        });
    controls::Grid::SetColumn(m_account, 1);
    header.Children().Append(m_account);
    m_page.Children().Append(header);

    m_disconnectedBody.VerticalAlignment(xaml::VerticalAlignment::Center);
    m_disconnectedProgress.Width(m_resources.Double(AppDouble::HomeProgressRingSize));
    m_disconnectedProgress.Height(m_resources.Double(AppDouble::HomeProgressRingSize));
    m_disconnectedProgress.HorizontalAlignment(xaml::HorizontalAlignment::Center);
    m_disconnectedBody.Children().Append(m_disconnectedProgress);

    m_disconnectedContent.VerticalAlignment(xaml::VerticalAlignment::Center);
    auto icon = m_uiFactory.Text(Glyphs::Network, AppStyle::TextNetworkGlyph);
    icon.HorizontalAlignment(xaml::HorizontalAlignment::Center);
    icon.Margin(m_resources.Thickness(AppThickness::DisconnectedIconMargin));
    m_disconnectedContent.Children().Append(icon);
    m_disconnectedMessage = m_uiFactory.Text(L"", AppStyle::TextTitle);
    m_disconnectedMessage.HorizontalAlignment(xaml::HorizontalAlignment::Center);
    m_disconnectedMessage.TextAlignment(xaml::TextAlignment::Center);
    m_disconnectedContent.Children().Append(m_disconnectedMessage);
    m_disconnectedDetail.Style(m_resources.Style(AppStyle::TextBody));
    m_disconnectedDetail.HorizontalAlignment(xaml::HorizontalAlignment::Center);
    m_disconnectedDetail.TextAlignment(xaml::TextAlignment::Center);
    m_disconnectedDetail.Margin(m_resources.Thickness(AppThickness::DisconnectedDetailMargin));
    m_disconnectedContent.Children().Append(m_disconnectedDetail);
    m_connectButton = m_buttonFactory.PrimaryText(L"");
    m_connectButton.Click(
        [this](const auto&, const auto&)
        {
            m_sessionController.ConnectStoredOrRequestSignIn();
        });
    m_disconnectedContent.Children().Append(m_connectButton);
    m_disconnectedBody.Children().Append(m_disconnectedContent);
    m_body.Children().Append(m_disconnectedBody);

    m_connectedBody.Margin(m_resources.Thickness(AppThickness::ConnectedBodyMargin));
    m_connectedBody.VerticalAlignment(xaml::VerticalAlignment::Stretch);
    auto exitNodeRow = controls::RowDefinition();
    exitNodeRow.Height(xaml::GridLengthHelper::Auto());
    m_connectedBody.RowDefinitions().Append(exitNodeRow);
    auto searchRow = controls::RowDefinition();
    searchRow.Height(xaml::GridLengthHelper::Auto());
    m_connectedBody.RowDefinitions().Append(searchRow);
    auto devicesRow = controls::RowDefinition();
    devicesRow.Height(xaml::GridLengthHelper::FromValueAndType(1, xaml::GridUnitType::Star));
    m_connectedBody.RowDefinitions().Append(devicesRow);
    m_connectedBody.Children().Append(m_exitNodeCard);

    m_search.PlaceholderText(m_resourceLoader.Get(Resources::Home::SearchPlaceholder));
    m_search.QueryIcon(controls::SymbolIcon(controls::Symbol::Find));
    m_search.Margin(m_resources.Thickness(AppThickness::SearchMargin));
    m_search.TextChanged(
        [this](const controls::AutoSuggestBox& sender,
               const controls::AutoSuggestBoxTextChangedEventArgs&)
        {
            m_controller.SearchText(sender.Text());
            RebuildDeviceItems();
        });
    controls::Grid::SetRow(m_search, 1);
    m_connectedBody.Children().Append(m_search);

    m_deviceList = m_uiFactory.PageListView();
    m_deviceList.HorizontalAlignment(xaml::HorizontalAlignment::Stretch);
    m_deviceList.VerticalAlignment(xaml::VerticalAlignment::Stretch);
    m_deviceList.ItemsPanel(
        m_resources.ItemsPanelTemplate(AppItemsPanelTemplate::StickyDeviceItems));
    controls::GroupStyle groupStyle;
    groupStyle.HeaderTemplate(m_resources.DataTemplate(AppDataTemplate::DeviceGroupHeader));
    groupStyle.HeaderContainerStyle(m_resources.Style(AppStyle::DeviceGroupHeader));
    m_deviceList.GroupStyle().Append(groupStyle);
    m_deviceGroups.IsSourceGrouped(true);
    m_deviceGroups.ItemsPath(xaml::PropertyPath(L"Items"));
    controls::Grid::SetRow(m_deviceList, 2);
    m_connectedBody.Children().Append(m_deviceList);
    m_body.Children().Append(m_connectedBody);

    controls::Grid::SetRow(m_body, 1);
    m_page.Children().Append(m_body);
}

void HomePageViewImpl::OnStateChange(const std::string& stateName)
{
    const SessionState& session = m_sessionController.GetState();
    m_presentation.Status = DisplayStatus();
    m_presentation.StatusStyle = StatusStyle();
    m_presentation.Connected = session.Connected();
    m_presentation.Busy = session.Busy();
    m_presentation.HasStoredProfile = m_state.HasStoredProfile();

    m_toggle.IsOn(m_presentation.Connected);
    m_toggle.IsEnabled(!m_presentation.Busy);
    m_tailnetTitle.Text(TailnetTitle(m_state, m_resourceLoader));
    m_status.Text(m_presentation.Status);
    m_status.Style(m_resources.Style(m_presentation.StatusStyle));
    const media::ImageSource profilePicture = m_profilePictureController.GetState().Image();
    if (profilePicture != nullptr)
    {
        m_account.Content(m_uiFactory.ProfilePicture(
            m_resources.Double(AppDouble::SmallProfilePictureSize), profilePicture));
    }
    else
    {
        m_account.Content(m_defaultAccountContent);
    }

    if (stateName == "profile-picture")
    {
        return;
    }

    const xaml::Visibility connectedVisibility =
        m_presentation.Connected ? xaml::Visibility::Visible : xaml::Visibility::Collapsed;
    const xaml::Visibility disconnectedVisibility =
        m_presentation.Connected ? xaml::Visibility::Collapsed : xaml::Visibility::Visible;
    m_connectedBody.Visibility(connectedVisibility);
    m_disconnectedBody.Visibility(disconnectedVisibility);
    m_disconnectedProgress.IsActive(m_presentation.Busy);
    m_disconnectedProgress.Visibility(m_presentation.Busy ? xaml::Visibility::Visible
                                                          : xaml::Visibility::Collapsed);
    m_disconnectedContent.Visibility(m_presentation.Busy ? xaml::Visibility::Collapsed
                                                         : xaml::Visibility::Visible);
    m_disconnectedMessage.Text(m_presentation.HasStoredProfile
                                   ? m_resourceLoader.Get(Resources::Common::NotConnected)
                                   : m_resourceLoader.Get(Resources::Home::Welcome));
    m_disconnectedDetail.Inlines().Clear();
    if (m_presentation.HasStoredProfile)
    {
        documents::Run message;
        message.Text(
            m_resourceLoader.Format(Resources::Home::ConnectDescription,
                                    std::wstring_view(TailnetTitle(m_state, m_resourceLoader))));
        m_disconnectedDetail.Inlines().Append(message);
    }
    else
    {
        documents::Run message;
        message.Text(m_resourceLoader.Get(Resources::Home::LogInDescription));
        m_disconnectedDetail.Inlines().Append(message);
    }
    m_connectButton.Content(foundation::PropertyValue::CreateString(
        m_presentation.HasStoredProfile ? m_resourceLoader.Get(Resources::Home::Connect)
                                        : m_resourceLoader.Get(Resources::Home::LogIn)));

    m_exitNodeCard.Children().Clear();
    m_exitNodeCard.Children().Append(BuildExitNodeCard());
    if (m_search.Text() != m_pageState.SearchText())
    {
        m_search.Text(m_pageState.SearchText());
    }
    RebuildDeviceItems();
}

winrt::hstring HomePageViewImpl::DisplayStatus() const
{
    const SessionState& session = m_sessionController.GetState();
    switch (session.Activity())
    {
    case SessionActivity::Checking:
    case SessionActivity::Starting:
        return m_resourceLoader.Get(Resources::Home::StartingStatus);
    case SessionActivity::Stopping:
        return m_resourceLoader.Get(Resources::Home::StoppingStatus);
    case SessionActivity::LoggingOut:
        return m_resourceLoader.Get(Resources::Home::LoggingOutStatus);
    case SessionActivity::ChangingSettings:
    case SessionActivity::Idle:
        break;
    }
    if (session.Error())
    {
        return m_resourceLoader.Get(*session.Error());
    }
    return session.Connected() ? m_resourceLoader.Get(Resources::Home::ConnectedStatus)
                               : m_resourceLoader.Get(Resources::Common::NotConnected);
}

AppStyle HomePageViewImpl::StatusStyle() const
{
    const SessionState& session = m_sessionController.GetState();
    if (!session.Busy() && session.Error())
    {
        return AppStyle::TextErrorStatus;
    }
    if (session.Busy() && session.Activity() != SessionActivity::ChangingSettings)
    {
        return AppStyle::TextOfflineStatus;
    }
    return session.Connected() ? AppStyle::TextOnlineStatus : AppStyle::TextOfflineStatus;
}

xaml::UIElement HomePageViewImpl::Page() const
{
    return m_page;
}

xaml::UIElement HomePageViewImpl::BuildExitNodeCard()
{
    const bool hasExitOption = std::any_of(m_state.Devices().begin(),
                                           m_state.Devices().end(),
                                           [](const UwpDevice& device)
                                           {
                                               return device.ExitNodeOption;
                                           });
    winrt::hstring selected = m_exitNodeController.GetState().Selection();
    const auto selectedDevice = std::find_if(m_state.Devices().begin(),
                                             m_state.Devices().end(),
                                             [&selected](const UwpDevice& device)
                                             {
                                                 return device.MatchesExitNode(selected);
                                             });
    if (!selected.empty() && selectedDevice == m_state.Devices().end())
    {
        selected.clear();
    }
    const winrt::hstring active = m_exitNodeController.GetState().Current();
    if (!hasExitOption && selected.empty())
    {
        return controls::StackPanel();
    }
    const bool enabled = !active.empty() && !selected.empty();
    const bool selectedOnline = selectedDevice == m_state.Devices().end() || selectedDevice->Online;
    const bool errorState = !selectedOnline;
    const bool emphasized = enabled || errorState;
    controls::Grid card;
    card.Style(m_resources.Style(errorState ? AppStyle::ErrorCard
                                 : enabled  ? AppStyle::AccentCard
                                            : AppStyle::NeutralCard));
    auto textColumn = controls::ColumnDefinition();
    textColumn.Width(xaml::GridLengthHelper::FromValueAndType(1, xaml::GridUnitType::Star));
    card.ColumnDefinitions().Append(textColumn);
    auto actionColumn = controls::ColumnDefinition();
    actionColumn.Width(xaml::GridLengthHelper::Auto());
    card.ColumnDefinitions().Append(actionColumn);

    controls::StackPanel textPanel;
    textPanel.VerticalAlignment(xaml::VerticalAlignment::Center);
    const AppStyle labelStyle = errorState ? AppStyle::TextOnErrorCaption
                                : enabled  ? AppStyle::TextOnEmphasisCaption
                                           : AppStyle::TextSecondaryCaptionStrong;
    auto label = m_uiFactory.Text(selectedOnline
                                      ? m_resourceLoader.Get(Resources::Home::ExitNodeLabel)
                                      : m_resourceLoader.Get(Resources::Home::ExitNodeOfflineLabel),
                                  labelStyle);
    label.Margin(m_resources.Thickness(AppThickness::CardLabelMargin));
    textPanel.Children().Append(label);
    controls::StackPanel choice;
    choice.Orientation(controls::Orientation::Horizontal);
    const AppStyle selectedStyle = errorState ? AppStyle::TextOnErrorSubtitle
                                   : enabled  ? AppStyle::TextOnEmphasisSubtitle
                                              : AppStyle::TextSubtitle;
    auto selectedText = m_uiFactory.Text(
        selected.empty() ? m_resourceLoader.Get(Resources::Home::None) : selected, selectedStyle);
    choice.Children().Append(selectedText);
    auto chevron = m_uiFactory.FluentIcon(Glyphs::ChevronDown);
    chevron.FontSize(m_resources.Double(AppDouble::ChevronFontSize));
    chevron.VerticalAlignment(xaml::VerticalAlignment::Center);
    chevron.Margin(m_resources.Thickness(AppThickness::CardChevronMargin));
    if (emphasized)
    {
        chevron.Foreground(m_resources.Brush(errorState ? AppBrush::OnError : AppBrush::OnAccent));
    }
    choice.Children().Append(chevron);
    textPanel.Children().Append(choice);

    controls::Button picker;
    picker.HorizontalAlignment(xaml::HorizontalAlignment::Stretch);
    picker.HorizontalContentAlignment(xaml::HorizontalAlignment::Left);
    picker.Style(m_resources.Style(AppStyle::TransparentButton));
    m_resources.Apply(picker, AppControlResources::TransparentButton);
    picker.Margin(m_resources.Thickness(selected.empty()
                                            ? AppThickness::CardPickerMargin
                                            : AppThickness::CardPickerWithActionMargin));
    picker.Content(textPanel);
    picker.Click(
        [this](const auto&, const auto&)
        {
            m_navigationController.OpenPage(NavigationControllerState::ExitNodes);
        });
    card.Children().Append(picker);

    if (!selected.empty())
    {
        auto toggle = m_buttonFactory.Text(enabled ? m_resourceLoader.Get(Resources::Home::Disable)
                                                   : m_resourceLoader.Get(Resources::Home::Enable));
        toggle.IsEnabled(!m_presentation.Busy);
        toggle.HorizontalAlignment(xaml::HorizontalAlignment::Right);
        toggle.VerticalAlignment(xaml::VerticalAlignment::Center);
        toggle.Margin(m_resources.Thickness(AppThickness::CardActionMargin));
        if (emphasized)
        {
            toggle.Style(m_resources.Style(errorState ? AppStyle::EmphasizedErrorButton
                                                      : AppStyle::EmphasizedButton));
            m_resources.Apply(toggle,
                              errorState ? AppControlResources::EmphasizedErrorButton
                                         : AppControlResources::EmphasizedButton);
        }
        toggle.Click(
            [this, enabled](const auto&, const auto&)
            {
                m_exitNodeController.SetEnabled(!enabled);
            });
        controls::Grid::SetColumn(toggle, 1);
        card.Children().Append(toggle);
    }

    controls::Border hoverSurface;
    hoverSurface.IsHitTestVisible(false);
    controls::Grid::SetColumnSpan(hoverSurface, 2);
    card.Children().Append(hoverSurface);
    const auto hoverBrush = m_resources.Brush(AppBrush::Hover);
    card.PointerEntered(
        [hoverSurface, hoverBrush](const auto&, const auto&)
        {
            hoverSurface.Background(hoverBrush);
        });
    card.PointerExited(
        [hoverSurface](const auto&, const auto&)
        {
            hoverSurface.Background(nullptr);
        });
    return card;
}

void HomePageViewImpl::RebuildDeviceItems()
{
    if (m_deviceList == nullptr)
    {
        return;
    }
    std::vector<std::pair<winrt::hstring, std::vector<const UwpDevice*>>> groups;
    for (const UwpDevice& device : m_state.Devices())
    {
        const std::wstring_view searchText(m_pageState.SearchText());
        if (!boost::algorithm::icontains(std::wstring_view(device.Name), searchText) &&
            !boost::algorithm::icontains(std::wstring_view(device.Address), searchText) &&
            !boost::algorithm::icontains(std::wstring_view(device.Group), searchText))
        {
            continue;
        }
        const auto found = std::find_if(groups.begin(),
                                        groups.end(),
                                        [&device](const auto& group)
                                        {
                                            return group.first == device.Group;
                                        });
        if (found == groups.end())
        {
            groups.push_back({device.Group, {&device}});
        }
        else
        {
            found->second.push_back(&device);
        }
    }
    const winrt::hstring selfAddress =
        m_state.Devices().empty() ? winrt::hstring{} : m_state.Devices().front().Address;
    auto groupedItems = winrt::single_threaded_observable_vector<foundation::IInspectable>();
    for (const auto& [groupName, devices] : groups)
    {
        auto items = winrt::single_threaded_observable_vector<foundation::IInspectable>();
        for (const UwpDevice* devicePointer : devices)
        {
            const UwpDevice device = *devicePointer;
            controls::StackPanel row;
            row.Orientation(controls::Orientation::Horizontal);
            row.Children().Append(m_uiFactory.StatusDot(device.Online));
            controls::StackPanel labels;
            labels.Margin(m_resources.Thickness(AppThickness::DeviceLabelsMargin));
            labels.Children().Append(
                m_uiFactory.Text(device.Name.empty() ? device.Address : device.ShortName(),
                                 AppStyle::TextBodyStrong));
            auto address = m_uiFactory.Text(device.Address, AppStyle::TextSecondaryCaption);
            labels.Children().Append(address);
            row.Children().Append(labels);

            auto item = m_uiFactory.ListItem(row);
            item.Tapped(
                [this, device](const auto&, const auto&)
                {
                    m_devicePageController.SelectDevice(device.Address);
                    m_navigationController.OpenPage(NavigationControllerState::Device);
                });

            const bool isSelf = !device.Address.empty() && device.Address == selfAddress;
            controls::MenuFlyout menu;
            controls::MenuFlyoutItem copyItem;
            copyItem.Text(m_resourceLoader.Get(Resources::Home::CopyIpAddress));
            copyItem.Icon(m_uiFactory.FluentIcon(Glyphs::Copy));
            copyItem.Click(
                [this, address = device.Address](const auto&, const auto&)
                {
                    m_clipboardController.SetText(address);
                });
            menu.Items().Append(copyItem);
            if (!isSelf)
            {
                controls::MenuFlyoutItem pingItem;
                pingItem.Text(m_resourceLoader.Get(Resources::Home::Ping));
                pingItem.Icon(m_uiFactory.FluentIcon(Glyphs::SpeedHigh));
                pingItem.Click(
                    [this, device, selfAddress](const auto&, const auto&)
                    {
                        const winrt::hstring deviceName =
                            device.Name.empty() ? device.Address : device.ShortName();
                        m_pingDialogController.Show(deviceName, device.Address, selfAddress);
                    });
                menu.Items().Append(pingItem);
            }
            item.ContextFlyout(menu);
            items.Append(item);
        }
        collections::PropertySet group;
        group.Insert(L"Name",
                     winrt::box_value(groupName.empty()
                                          ? m_resourceLoader.Get(Resources::Home::OtherDevices)
                                          : groupName));
        group.Insert(L"Items", items);
        groupedItems.Append(group);
    }
    m_deviceGroups.Source(groupedItems);
    m_deviceList.ItemsSource(m_deviceGroups.View());
}

} // namespace tailgate::uwp
