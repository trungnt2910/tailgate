#include "app/view/impl/SignInDialogViewImpl.h"

#include <optional>

#include <winrt/Windows.UI.Xaml.Input.h>

#include "common/ResourceLoader.h"
#include "common/UwpMachineIdentity.h"
#include "strings/Resources.h"

#include "app/controller/SignInDialogController.h"
#include "app/model/SignInDialogState.h"
#include "app/ui/AppResources.h"
#include "app/ui/Glyphs.h"
#include "app/ui/UiFactory.h"

namespace tailgate::uwp
{

SignInDialogViewImpl::SignInDialogViewImpl(AppResources& resources,
                                           ResourceLoader& resourceLoader,
                                           UiFactory& uiFactory,
                                           SignInDialogController& controller)
    : m_state(controller.GetState()),
      m_controller(controller),
      m_resources(resources),
      m_resourceLoader(resourceLoader),
      m_uiFactory(uiFactory)
{
    Subscribe(m_state, "sign-in");
    Initialize();
}

void SignInDialogViewImpl::Render()
{
    m_panel = controls::StackPanel();
    m_panel.HorizontalAlignment(xaml::HorizontalAlignment::Stretch);
    m_panel.VerticalAlignment(xaml::VerticalAlignment::Center);

    m_tailgateBox = controls::TextBox();
    m_tailgateBox.Header(foundation::PropertyValue::CreateString(
        m_resourceLoader.Get(Resources::Brand::ProductName)));
    m_tailgateBox.PlaceholderText(m_resourceLoader.Get(Resources::SignIn::ServerExample));
    m_tailgateBox.HorizontalAlignment(xaml::HorizontalAlignment::Stretch);
    m_tailgateBox.TextChanged(
        [this](const foundation::IInspectable& sender, const auto&)
        {
            m_controller.OnTailgateServerChanged(sender.as<controls::TextBox>().Text());
        });
    m_panel.Children().Append(m_tailgateBox);

    m_validationError = m_uiFactory.Text(m_resourceLoader.Get(Resources::SignIn::ServerRequired),
                                         AppStyle::TextErrorSmall);
    m_validationError.Margin(m_resources.Thickness(AppThickness::FieldSpacingMargin));
    m_panel.Children().Append(m_validationError);

    m_advancedHeader = controls::Button();
    m_advancedHeader.HorizontalAlignment(xaml::HorizontalAlignment::Stretch);
    m_advancedHeader.HorizontalContentAlignment(xaml::HorizontalAlignment::Left);
    m_advancedHeader.Margin(m_resources.Thickness(AppThickness::DialogSectionMargin));
    m_advancedHeader.Padding(m_resources.Thickness(AppThickness::AdvancedButtonPadding));
    m_advancedHeader.BorderThickness(m_resources.Thickness(AppThickness::Zero));
    auto advancedHeaderContent = controls::StackPanel();
    advancedHeaderContent.Orientation(controls::Orientation::Horizontal);
    m_advancedChevron = m_uiFactory.FluentIcon(Glyphs::ChevronRight);
    m_advancedChevron.FontSize(m_resources.Double(AppDouble::ChevronFontSize));
    m_advancedChevron.VerticalAlignment(xaml::VerticalAlignment::Center);
    m_advancedChevron.Margin(m_resources.Thickness(AppThickness::AdvancedChevronMargin));
    advancedHeaderContent.Children().Append(m_advancedChevron);
    advancedHeaderContent.Children().Append(
        m_uiFactory.Text(m_resourceLoader.Get(Resources::SignIn::Advanced), AppStyle::TextStatus));
    m_advancedHeader.Content(advancedHeaderContent);
    m_advancedHeader.Click(
        [this](const auto&, const auto&)
        {
            m_controller.OnAdvancedClicked();
        });
    m_advancedHeader.PointerEntered(
        [this](const auto&, const auto&)
        {
            m_controller.OnAdvancedPointerEntered();
        });
    m_advancedHeader.PointerExited(
        [this](const auto&, const auto&)
        {
            m_controller.OnAdvancedPointerExited();
        });
    m_panel.Children().Append(m_advancedHeader);

    m_authKeyBox = controls::PasswordBox();
    m_authKeyBox.Header(foundation::PropertyValue::CreateString(
        m_resourceLoader.Get(Resources::SignIn::AuthKeyHeader)));
    m_authKeyBox.PlaceholderText(m_resourceLoader.Get(Resources::SignIn::AuthKeyPlaceholder));
    m_authKeyBox.Margin(m_resources.Thickness(AppThickness::FieldSpacingMargin));
    m_authKeyBox.HorizontalAlignment(xaml::HorizontalAlignment::Stretch);
    m_authKeyBox.PasswordChanged(
        [this](const foundation::IInspectable& sender, const auto&)
        {
            m_controller.OnAuthKeyChanged(sender.as<controls::PasswordBox>().Password());
        });
    m_panel.Children().Append(m_authKeyBox);

    m_hostnameBox = controls::TextBox();
    m_hostnameBox.Header(foundation::PropertyValue::CreateString(
        m_resourceLoader.Get(Resources::SignIn::HostnameHeader)));
    m_hostnameBox.PlaceholderText(winrt::to_hstring(CollectComputerHostname()));
    m_hostnameBox.Margin(m_resources.Thickness(AppThickness::FieldSpacingMargin));
    m_hostnameBox.HorizontalAlignment(xaml::HorizontalAlignment::Stretch);
    m_hostnameBox.TextChanged(
        [this](const foundation::IInspectable& sender, const auto&)
        {
            m_controller.OnHostnameChanged(sender.as<controls::TextBox>().Text());
        });
    m_panel.Children().Append(m_hostnameBox);

    m_errorText = m_uiFactory.Text(L"", AppStyle::TextErrorSmall);
    m_errorText.Margin(m_resources.Thickness(AppThickness::DialogSectionMargin));
    m_panel.Children().Append(m_errorText);

    m_dialog = CreateContentDialog();
    m_dialog.Title(
        foundation::PropertyValue::CreateString(m_resourceLoader.Get(Resources::SignIn::Title)));
    m_dialog.Content(m_panel);
    m_dialog.PrimaryButtonText(m_resourceLoader.Get(Resources::SignIn::Title));
    m_dialog.CloseButtonText(m_resourceLoader.Get(Resources::Common::Cancel));
    m_dialog.DefaultButton(controls::ContentDialogButton::Primary);
    m_dialog.PrimaryButtonClick(
        [this](const auto&, const controls::ContentDialogButtonClickEventArgs& args)
        {
            m_controller.OnPrimaryButtonClick();
            args.Cancel(m_state.ValidationErrorVisible());
        });
}

controls::ContentDialog SignInDialogViewImpl::Dialog() const
{
    return m_dialog;
}

void SignInDialogViewImpl::OnClosed(controls::ContentDialogResult result)
{
    m_controller.OnClosed(result);
}

void SignInDialogViewImpl::OnStateChange(const std::string&)
{
    const SignInDialogState& state = m_state;
    if (m_tailgateBox.Text() != state.TailgateServer())
    {
        m_tailgateBox.Text(state.TailgateServer());
    }
    if (m_authKeyBox.Password() != state.AuthKey())
    {
        m_authKeyBox.Password(state.AuthKey());
    }
    if (m_hostnameBox.Text() != state.Hostname())
    {
        m_hostnameBox.Text(state.Hostname());
    }

    m_validationError.Visibility(state.ValidationErrorVisible() ? xaml::Visibility::Visible
                                                                : xaml::Visibility::Collapsed);
    m_advancedHeader.Background(state.AdvancedHovered() ? m_resources.Brush(AppBrush::Hover)
                                                        : m_resources.Brush(AppBrush::Transparent));
    m_advancedChevron.Glyph(state.AdvancedExpanded() ? Glyphs::ChevronDown : Glyphs::ChevronRight);
    const xaml::Visibility advancedVisibility =
        state.AdvancedExpanded() ? xaml::Visibility::Visible : xaml::Visibility::Collapsed;
    m_authKeyBox.Visibility(advancedVisibility);
    m_hostnameBox.Visibility(advancedVisibility);
    const std::optional<UwpError::Code> error = state.Error();
    m_errorText.Text(error ? m_resourceLoader.Get(*error) : L"");
    m_errorText.Visibility(error ? xaml::Visibility::Visible : xaml::Visibility::Collapsed);
}

} // namespace tailgate::uwp
