#pragma once

#include "app/view/SignInDialogView.h"

namespace tailgate::uwp
{

class AppResources;
class ResourceLoader;
class SignInDialogController;
class SignInDialogState;
class UiFactory;

class SignInDialogViewImpl final : public SignInDialogView
{
public:
    SignInDialogViewImpl(AppResources& resources,
                         ResourceLoader& resourceLoader,
                         UiFactory& uiFactory,
                         SignInDialogController& controller);

    SignInDialogViewImpl(const SignInDialogViewImpl&) = delete;
    SignInDialogViewImpl& operator=(const SignInDialogViewImpl&) = delete;

    [[nodiscard]] controls::ContentDialog Dialog() const override;
    void OnClosed(controls::ContentDialogResult result) override;

private:
    void Render() override;
    void OnStateChange(const std::string& stateName) override;

    const SignInDialogState& m_state;
    SignInDialogController& m_controller;
    AppResources& m_resources;
    ResourceLoader& m_resourceLoader;
    controls::ContentDialog m_dialog;
    controls::StackPanel m_panel;
    controls::TextBox m_tailgateBox;
    controls::TextBlock m_validationError;
    controls::Button m_advancedHeader;
    controls::FontIcon m_advancedChevron;
    controls::PasswordBox m_authKeyBox;
    controls::TextBox m_hostnameBox;
    controls::TextBlock m_errorText;
    UiFactory& m_uiFactory;
};

} // namespace tailgate::uwp
