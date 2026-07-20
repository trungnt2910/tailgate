#pragma once

#include "app/view/PingDialogView.h"

namespace tailgate::uwp
{

class AppResources;
class PingController;
class PingDialogController;
class PingDialogState;
class PingState;
class ResourceLoader;
class UiFactory;

class PingDialogViewImpl final : public PingDialogView
{
public:
    PingDialogViewImpl(AppResources& resources,
                       ResourceLoader& resourceLoader,
                       UiFactory& uiFactory,
                       PingController& pingController,
                       PingDialogController& controller);

    PingDialogViewImpl(const PingDialogViewImpl&) = delete;
    PingDialogViewImpl& operator=(const PingDialogViewImpl&) = delete;

    [[nodiscard]] controls::ContentDialog Dialog() const override;
    void OnClosed(controls::ContentDialogResult result) override;

private:
    void Render() override;
    void OnStateChange(const std::string& stateName) override;
    void SetBody(const xaml::UIElement& content);

    const PingDialogState& m_state;
    const PingState& m_pingState;
    PingDialogController& m_controller;
    AppResources& m_resources;
    ResourceLoader& m_resourceLoader;
    controls::ContentDialog m_dialog;
    controls::TextBlock m_titleText;
    controls::TextBlock m_latencyText;
    controls::ContentControl m_connectionHost;
    controls::Grid m_body;
    UiFactory& m_uiFactory;
};

} // namespace tailgate::uwp
