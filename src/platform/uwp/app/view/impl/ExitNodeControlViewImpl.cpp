#include "app/view/impl/ExitNodeControlViewImpl.h"

#include <algorithm>
#include <utility>

#include <winrt/Windows.UI.Xaml.Input.h>

#include "common/ResourceLoader.h"
#include "strings/Resources.h"

#include "app/controller/ExitNodeController.h"
#include "app/controller/NavigationController.h"
#include "app/controller/SessionController.h"
#include "app/controller/SettingsController.h"
#include "app/ui/AppResources.h"
#include "app/ui/Glyphs.h"
#include "app/ui/UiFactory.h"

namespace tailgate::uwp
{

ExitNodeControlViewImpl::ExitNodeControlViewImpl(AppResources& resources,
                                                 ResourceLoader& resourceLoader,
                                                 UiFactory& uiFactory,
                                                 ExitNodeController& exitNodeController,
                                                 NavigationController& navigationController,
                                                 SessionController& sessionController,
                                                 SettingsController& settingsController)
    : m_resources(resources),
      m_resourceLoader(resourceLoader),
      m_uiFactory(uiFactory),
      m_exitNodeController(exitNodeController),
      m_navigationController(navigationController),
      m_sessionController(sessionController),
      m_settingsController(settingsController)
{
    Subscribe(m_settingsController.GetState(), "settings");
    Subscribe(m_sessionController.GetState(), "session");
    Initialize();
}

void ExitNodeControlViewImpl::Render()
{
    m_page.HorizontalContentAlignment(xaml::HorizontalAlignment::Stretch);
    m_page.VerticalContentAlignment(xaml::VerticalAlignment::Stretch);
    m_list = m_uiFactory.PageListView();
    m_page.Content(
        m_uiFactory.PageChrome(m_resourceLoader.Get(Resources::ExitNode::ChooseTitle), m_list));
}

void ExitNodeControlViewImpl::OnStateChange(const std::string&)
{
    AppResources& resources = m_resources;
    UiFactory& uiFactory = m_uiFactory;
    ExitNodeController& exitNodeController = m_exitNodeController;
    NavigationController& navigationController = m_navigationController;
    SessionController& sessionController = m_sessionController;
    SettingsController& settingsController = m_settingsController;
    const SettingsState& settings = settingsController.GetState();
    const bool busy = sessionController.GetState().Busy();
    const winrt::hstring storedSelection = exitNodeController.GetState().Selection();
    winrt::hstring selected = storedSelection;
    const bool selectedPeerExists = std::any_of(settings.Devices().begin(),
                                                settings.Devices().end(),
                                                [&selected](const UwpDevice& device)
                                                {
                                                    return device.MatchesExitNode(selected);
                                                });
    if (!selected.empty() && !selectedPeerExists)
    {
        selected.clear();
    }
    m_list.Items().Clear();
    const auto addChoice = [&](const winrt::hstring& title,
                               const winrt::hstring& secondary,
                               bool checked,
                               bool available,
                               std::function<void()> onClick)
    {
        controls::Grid row;
        auto textColumn = controls::ColumnDefinition();
        textColumn.Width(xaml::GridLengthHelper::FromValueAndType(1, xaml::GridUnitType::Star));
        row.ColumnDefinitions().Append(textColumn);
        auto checkColumn = controls::ColumnDefinition();
        checkColumn.Width(xaml::GridLengthHelper::Auto());
        row.ColumnDefinitions().Append(checkColumn);
        controls::StackPanel labels;
        labels.Children().Append(uiFactory.Text(title, AppStyle::TextBody));
        if (!secondary.empty())
        {
            auto secondaryBlock = uiFactory.Text(secondary, AppStyle::TextSecondaryCaption);
            labels.Children().Append(secondaryBlock);
        }
        row.Children().Append(labels);
        if (checked)
        {
            auto tick = uiFactory.FluentIcon(Glyphs::CheckMark);
            tick.Foreground(resources.Brush(AppBrush::Accent));
            tick.VerticalAlignment(xaml::VerticalAlignment::Center);
            controls::Grid::SetColumn(tick, 1);
            row.Children().Append(tick);
        }
        const bool clickable = available && !busy;
        auto item = uiFactory.ListItem(row);
        item.IsEnabled(clickable);
        item.Tapped(
            [clickable, onClick = std::move(onClick)](const auto&, const auto&)
            {
                if (clickable)
                {
                    onClick();
                }
            });
        m_list.Items().Append(item);
    };

    addChoice(m_resourceLoader.Get(Resources::ExitNode::None),
              L"",
              selected.empty(),
              true,
              [&exitNodeController, &navigationController]()
              {
                  exitNodeController.SetNode(L"");
                  navigationController.Back();
              });
    addChoice(m_resourceLoader.Get(Resources::ExitNode::RunAsExitNode),
              m_resourceLoader.Get(Resources::Common::Disabled),
              false,
              false,
              []
              {
              });
    m_list.Items().Append(uiFactory.SectionSpacing());
    for (const UwpDevice& device : settings.Devices())
    {
        if (!device.ExitNodeOption)
        {
            continue;
        }
        const winrt::hstring name = device.ShortName();
        addChoice(name,
                  device.Online ? winrt::hstring{}
                                : m_resourceLoader.Get(Resources::Common::Offline),
                  device.MatchesExitNode(selected),
                  device.Online,
                  [&exitNodeController, &navigationController, name]()
                  {
                      exitNodeController.SetNode(name);
                      navigationController.Back();
                  });
    }
}

xaml::UIElement ExitNodeControlViewImpl::Page() const
{
    return m_page;
}

} // namespace tailgate::uwp
