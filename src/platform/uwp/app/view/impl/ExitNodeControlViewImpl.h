#pragma once

#include "app/view/ExitNodeControlView.h"

namespace tailgate::uwp
{

class AppResources;
class ExitNodeController;
class NavigationController;
class ResourceLoader;
class SessionController;
class SettingsController;
class UiFactory;

class ExitNodeControlViewImpl final : public ExitNodeControlView
{
public:
    ExitNodeControlViewImpl(AppResources& resources,
                            ResourceLoader& resourceLoader,
                            UiFactory& uiFactory,
                            ExitNodeController& exitNodeController,
                            NavigationController& navigationController,
                            SessionController& sessionController,
                            SettingsController& settingsController);

    [[nodiscard]] xaml::UIElement Page() const override;

private:
    void Render() override;
    void OnStateChange(const std::string& stateName) override;

    AppResources& m_resources;
    ResourceLoader& m_resourceLoader;
    UiFactory& m_uiFactory;
    ExitNodeController& m_exitNodeController;
    NavigationController& m_navigationController;
    SessionController& m_sessionController;
    SettingsController& m_settingsController;
    controls::ContentControl m_page;
    controls::ListView m_list;
};

} // namespace tailgate::uwp
