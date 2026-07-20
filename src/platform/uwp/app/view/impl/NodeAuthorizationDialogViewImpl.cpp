#include "app/view/impl/NodeAuthorizationDialogViewImpl.h"

#include <exception>
#include <string>

#include <tailgate/QrCode.h>
#include <tailgate/protocol/ControlRequests.h>

#include "common/ResourceLoader.h"
#include "strings/Resources.h"

#include "app/controller/NodeAuthorizationDialogController.h"
#include "app/controller/SessionController.h"
#include "app/model/NodeAuthorizationDialogState.h"
#include "app/ui/AppResources.h"
#include "app/ui/UiFactory.h"

namespace tailgate::uwp
{
namespace
{

constexpr int QrQuietZoneModules = 4;

controls::Canvas LoginQrCanvas(const std::string& authorizationUrl, AppResources& resources)
{
    const tailgate::QrCode code = tailgate::EncodeQrCode(authorizationUrl);
    const int totalModules = code.Size + (QrQuietZoneModules * 2);
    const double moduleSize = resources.Double(AppDouble::QrModuleSize);
    controls::Canvas canvas;
    canvas.Width(totalModules * moduleSize);
    canvas.Height(totalModules * moduleSize);
    canvas.Background(resources.Brush(AppBrush::QrBackground));
    canvas.HorizontalAlignment(xaml::HorizontalAlignment::Center);
    canvas.VerticalAlignment(xaml::VerticalAlignment::Center);
    for (int y = 0; y < code.Size; ++y)
    {
        for (int x = 0; x < code.Size; ++x)
        {
            if (!code.Module(x, y))
            {
                continue;
            }
            shapes::Rectangle module;
            module.Width(moduleSize);
            module.Height(moduleSize);
            module.Fill(resources.Brush(AppBrush::QrForeground));
            controls::Canvas::SetLeft(module, (x + QrQuietZoneModules) * moduleSize);
            controls::Canvas::SetTop(module, (y + QrQuietZoneModules) * moduleSize);
            canvas.Children().Append(module);
        }
    }
    return canvas;
}

} // namespace

NodeAuthorizationDialogViewImpl::NodeAuthorizationDialogViewImpl(
    AppResources& resources,
    ResourceLoader& resourceLoader,
    UiFactory& uiFactory,
    NodeAuthorizationDialogController& controller,
    SessionController& sessionController)
    : m_state(controller.GetState()),
      m_controller(controller),
      m_sessionController(sessionController),
      m_resources(resources),
      m_resourceLoader(resourceLoader),
      m_uiFactory(uiFactory)
{
    Subscribe(m_state, "authorization");
    Initialize();
}

void NodeAuthorizationDialogViewImpl::Render()
{
    m_panel = controls::StackPanel();
    m_panel.HorizontalAlignment(xaml::HorizontalAlignment::Stretch);
    m_panel.VerticalAlignment(xaml::VerticalAlignment::Center);

    m_dialog = CreateContentDialog();
    m_dialog.Content(m_panel);
    m_dialog.CloseButtonText(m_resourceLoader.Get(Resources::Common::Dismiss));
    m_dialog.DefaultButton(controls::ContentDialogButton::Primary);
    m_dialog.PrimaryButtonClick(
        [this](const auto&, const controls::ContentDialogButtonClickEventArgs& args)
        {
            m_controller.OnPrimaryButtonClick();
            args.Cancel(true);
        });
    m_dialog.CloseButtonClick(
        [this](const auto&, const controls::ContentDialogButtonClickEventArgs&)
        {
            m_controller.OnCloseButtonClick();
            m_sessionController.CancelActiveConnectionAttempt();
        });
}

controls::ContentDialog NodeAuthorizationDialogViewImpl::Dialog() const
{
    return m_dialog;
}

void NodeAuthorizationDialogViewImpl::OnStateChange(const std::string&)
{
    const NodeAuthorizationDialogState& state = m_state;
    m_dialog.Title(foundation::PropertyValue::CreateString(
        state.MachineApproval()
            ? m_resourceLoader.Get(Resources::Authorization::ApprovalRequiredTitle)
            : m_resourceLoader.Get(Resources::Authorization::LoginRequiredTitle)));
    m_dialog.PrimaryButtonText(
        state.MachineApproval() ? m_resourceLoader.Get(Resources::Authorization::OpenApprovalPage)
                                : m_resourceLoader.Get(Resources::Authorization::OpenLoginPage));
    if (m_renderedUrl == state.Url() && m_renderedMachineApproval == state.MachineApproval())
    {
        return;
    }
    m_renderedUrl = state.Url();
    m_renderedMachineApproval = state.MachineApproval();
    m_panel.Children().Clear();
    if (state.Url().empty())
    {
        return;
    }

    const std::string authorizationUrl = winrt::to_string(state.Url());
    auto instructions =
        m_uiFactory.Text(state.MachineApproval()
                             ? m_resourceLoader.Get(Resources::Authorization::ApprovalInstructions)
                             : m_resourceLoader.Get(Resources::Authorization::LoginInstructions),
                         AppStyle::TextSubtitleStrong);
    instructions.TextAlignment(xaml::TextAlignment::Center);
    instructions.Margin(m_resources.Thickness(AppThickness::DialogInstructionsMargin));
    m_panel.Children().Append(instructions);
    try
    {
        m_panel.Children().Append(LoginQrCanvas(authorizationUrl, m_resources));
    }
    catch (const std::exception& error)
    {
        m_logger.LogWarning("unable to generate authorization QR code: {}", error.what());
        instructions.Text(m_resourceLoader.Get(Resources::Authorization::FallbackInstructions));
        auto url = m_uiFactory.Text(state.Url(), AppStyle::TextCaption);
        url.TextAlignment(xaml::TextAlignment::Center);
        m_panel.Children().Append(url);
    }

    const std::string authorizationCode = tailgate::protocol::AuthorizationCode(authorizationUrl);
    if (!authorizationCode.empty())
    {
        auto codeInstructions = m_uiFactory.Text(
            m_resourceLoader.Get(Resources::Authorization::AuthorizationCodeInstructions),
            AppStyle::TextSmall);
        codeInstructions.TextAlignment(xaml::TextAlignment::Center);
        codeInstructions.Margin(m_resources.Thickness(AppThickness::DialogCodeInstructionsMargin));
        m_panel.Children().Append(codeInstructions);
        auto code = m_uiFactory.Text(winrt::to_hstring(authorizationCode), AppStyle::TextCode);
        code.IsTextSelectionEnabled(true);
        code.TextAlignment(xaml::TextAlignment::Center);
        m_panel.Children().Append(code);
    }
}

} // namespace tailgate::uwp
