#include "app/view/impl/DevicePageViewImpl.h"

#include <algorithm>
#include <utility>

#include <winrt/Windows.UI.Xaml.Input.h>

#include "common/ResourceLoader.h"
#include "strings/Resources.h"

#include "app/controller/ClipboardController.h"
#include "app/controller/DevicePageController.h"
#include "app/controller/PingDialogController.h"
#include "app/controller/SettingsController.h"
#include "app/ui/AppResources.h"
#include "app/ui/ButtonFactory.h"
#include "app/ui/Glyphs.h"
#include "app/ui/UiFactory.h"

namespace tailgate::uwp
{

DevicePageViewImpl::DevicePageViewImpl(AppResources& resources,
                                       ResourceLoader& resourceLoader,
                                       ButtonFactory& buttonFactory,
                                       UiFactory& uiFactory,
                                       ClipboardController& clipboardController,
                                       DevicePageController& devicePageController,
                                       PingDialogController& pingDialogController,
                                       SettingsController& settingsController)
    : m_resources(resources),
      m_resourceLoader(resourceLoader),
      m_buttonFactory(buttonFactory),
      m_uiFactory(uiFactory),
      m_clipboardController(clipboardController),
      m_devicePageController(devicePageController),
      m_pingDialogController(pingDialogController),
      m_settingsController(settingsController)
{
    Subscribe(m_devicePageController.GetState(), "device");
    Subscribe(m_settingsController.GetState(), "settings");
    Initialize();
}

void DevicePageViewImpl::Render()
{
    m_page.HorizontalContentAlignment(xaml::HorizontalAlignment::Stretch);
    m_page.VerticalContentAlignment(xaml::VerticalAlignment::Stretch);

    controls::Grid header;
    header.Margin(m_resources.Thickness(AppThickness::PageTitleMargin));
    auto titleColumn = controls::ColumnDefinition();
    titleColumn.Width(xaml::GridLengthHelper::FromValueAndType(1, xaml::GridUnitType::Star));
    header.ColumnDefinitions().Append(titleColumn);
    auto pingColumn = controls::ColumnDefinition();
    pingColumn.Width(xaml::GridLengthHelper::Auto());
    header.ColumnDefinitions().Append(pingColumn);

    controls::StackPanel titleText;
    m_deviceName = m_uiFactory.Text(L"", AppStyle::TextPageTitle);
    titleText.Children().Append(m_deviceName);
    controls::StackPanel statusRow;
    statusRow.Orientation(controls::Orientation::Horizontal);
    statusRow.Margin(m_resources.Thickness(AppThickness::StatusRowMargin));
    statusRow.Children().Append(m_statusDot);
    m_status = m_uiFactory.Text(L"", AppStyle::TextStatus);
    m_status.Margin(m_resources.Thickness(AppThickness::StatusTextMargin));
    statusRow.Children().Append(m_status);
    titleText.Children().Append(statusRow);
    header.Children().Append(titleText);

    m_pingButton = m_buttonFactory.CircleIcon(Glyphs::SpeedHigh,
                                              m_resourceLoader.Get(Resources::Home::Ping),
                                              m_resources.Double(AppDouble::DevicePingIconSize));
    m_pingButton.VerticalAlignment(xaml::VerticalAlignment::Center);
    m_pingButton.Click(
        [this](const auto&, const auto&)
        {
            const UwpDevice* selected = SelectedDevice();
            if (selected == nullptr)
            {
                return;
            }
            const SettingsState& settings = m_settingsController.GetState();
            winrt::hstring selfAddress = settings.SelfAddress();
            if (selfAddress.empty() && !settings.Devices().empty())
            {
                selfAddress = settings.Devices().front().Address;
            }
            const winrt::hstring deviceName =
                selected->Name.empty() ? selected->Address : selected->ShortName();
            m_pingDialogController.Show(deviceName, selected->Address, selfAddress);
        });
    controls::Grid::SetColumn(m_pingButton, 1);
    header.Children().Append(m_pingButton);

    m_details = m_uiFactory.PageListView();

    controls::Grid content;
    content.Style(m_resources.Style(AppStyle::Page));
    auto headerRow = controls::RowDefinition();
    headerRow.Height(xaml::GridLengthHelper::Auto());
    content.RowDefinitions().Append(headerRow);
    auto contentRow = controls::RowDefinition();
    contentRow.Height(xaml::GridLengthHelper::FromValueAndType(1, xaml::GridUnitType::Star));
    content.RowDefinitions().Append(contentRow);
    content.Children().Append(header);
    controls::Grid::SetRow(m_details, 1);
    content.Children().Append(m_details);
    m_page.Content(content);
}

void DevicePageViewImpl::OnStateChange(const std::string&)
{
    const UwpDevice* selected = SelectedDevice();
    if (selected == nullptr)
    {
        return;
    }

    const UwpDevice device = *selected;
    m_deviceName.Text(device.Name.empty() ? device.Address : device.ShortName());
    m_statusDot.Children().Clear();
    m_statusDot.Children().Append(m_uiFactory.StatusDot(device.Online));
    m_status.Text(device.Online ? m_resourceLoader.Get(Resources::Common::Connected)
                                : m_resourceLoader.Get(Resources::Common::NotConnected));

    m_details.Items().Clear();
    m_details.Items().Append(
        m_uiFactory.ListHeader(m_resourceLoader.Get(Resources::Device::TailscaleAddresses)));
    const std::pair<winrt::hstring, winrt::hstring> addresses[] = {
        {device.MagicDnsName(), m_resourceLoader.Get(Resources::Device::MagicDns)},
        {device.Address, m_resourceLoader.Get(Resources::Device::Ipv4)},
        {device.Ipv6, m_resourceLoader.Get(Resources::Device::Ipv6)},
    };
    for (const auto& [value, label] : addresses)
    {
        if (value.empty())
        {
            continue;
        }
        auto item = m_uiFactory.ListItem(m_uiFactory.ValueWithIconRow(
            value, label, Glyphs::Copy, m_resources.Brush(AppBrush::Accent)));
        item.Tapped(
            [clipboardController = &m_clipboardController, value](const auto&, const auto&)
            {
                clipboardController->SetText(value);
            });
        m_details.Items().Append(item);
    }
    if (!device.OperatingSystem.empty())
    {
        m_details.Items().Append(m_uiFactory.SectionSpacing());
        controls::StackPanel osText;
        osText.Children().Append(m_uiFactory.Text(
            m_resourceLoader.Get(Resources::Device::OperatingSystem), AppStyle::TextBody));
        osText.Children().Append(
            m_uiFactory.Text(device.OperatingSystem, AppStyle::TextSecondaryCaption));
        m_details.Items().Append(m_uiFactory.ListItem(osText));
    }
}

const UwpDevice* DevicePageViewImpl::SelectedDevice() const
{
    const SettingsState& settings = m_settingsController.GetState();
    const winrt::hstring& selectedId = m_devicePageController.GetState().SelectedDeviceId();
    const auto selected =
        std::find_if(settings.Devices().begin(),
                     settings.Devices().end(),
                     [&selectedId](const UwpDevice& device)
                     {
                         return device.Address == selectedId || device.Name == selectedId;
                     });
    return selected == settings.Devices().end() ? nullptr : &*selected;
}

xaml::UIElement DevicePageViewImpl::Page() const
{
    return m_page;
}

} // namespace tailgate::uwp
