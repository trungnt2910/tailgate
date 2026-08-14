#pragma once

#include <tailgate/base/Logger.h>

#include "common/UwpFormat.h"

#include "app/view/NodeAuthorizationDialogView.h"

namespace tailgate::uwp
{

class AppResources;
class NodeAuthorizationDialogController;
class NodeAuthorizationDialogState;
class ResourceLoader;
class SessionController;
class UiFactory;

class NodeAuthorizationDialogViewImpl final : public NodeAuthorizationDialogView
{
public:
    NodeAuthorizationDialogViewImpl(AppResources& resources,
                                    ResourceLoader& resourceLoader,
                                    UiFactory& uiFactory,
                                    NodeAuthorizationDialogController& controller,
                                    SessionController& sessionController);

    NodeAuthorizationDialogViewImpl(const NodeAuthorizationDialogViewImpl&) = delete;
    NodeAuthorizationDialogViewImpl& operator=(const NodeAuthorizationDialogViewImpl&) = delete;

    [[nodiscard]] controls::ContentDialog Dialog() const override;

private:
    void Render() override;
    void OnStateChange(const std::string& stateName) override;

    const NodeAuthorizationDialogState& m_state;
    NodeAuthorizationDialogController& m_controller;
    SessionController& m_sessionController;
    AppResources& m_resources;
    ResourceLoader& m_resourceLoader;
    controls::ContentDialog m_dialog;
    controls::StackPanel m_panel;
    UiFactory& m_uiFactory;
    winrt::hstring m_renderedUrl;
    bool m_renderedMachineApproval = false;
    tailgate::base::Logger m_logger{"uwp-node-auth-dialog-view"};
};

} // namespace tailgate::uwp
