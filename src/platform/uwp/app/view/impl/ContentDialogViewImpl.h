#pragma once

#include <cstdint>
#include <memory>

#include <tailgate/base/Logger.h>

#include "common/UwpFormat.h"

#include "common/UwpAliases.h"

#include "app/model/ContentDialogState.h"
#include "app/view/ContentDialogView.h"

namespace tailgate::uwp
{

class ContentDialogController;
class DialogView;
class NodeAuthorizationDialogView;
class PingDialogView;
class SignInDialogView;

class ContentDialogViewImpl final : public ContentDialogView
{
public:
    ContentDialogViewImpl(ContentDialogController& controller,
                          std::unique_ptr<NodeAuthorizationDialogView> nodeAuthorizationDialog,
                          std::unique_ptr<PingDialogView> pingDialog,
                          std::unique_ptr<SignInDialogView> signInDialog);

private:
    void Render() override;
    void OnStateChange(const std::string& stateName) override;
    [[nodiscard]] DialogView& View(ContentDialogControllerState state) const;
    [[nodiscard]] foundation::IAsyncAction
    PresentAsync(DialogView& view, ContentDialogControllerState state, std::uint64_t generation);
    void UpdateDialog();

    ContentDialogController& m_controller;
    std::unique_ptr<NodeAuthorizationDialogView> m_nodeAuthorizationDialog;
    std::unique_ptr<PingDialogView> m_pingDialog;
    std::unique_ptr<SignInDialogView> m_signInDialog;
    DialogView* m_view = nullptr;
    controls::ContentDialog m_dialog = nullptr;
    ContentDialogControllerState m_state = ContentDialogControllerState::None;
    std::uint64_t m_generation = 0;
    std::uint64_t m_desiredGeneration = 0;
    bool m_hiding = false;
    tailgate::base::Logger m_logger{"uwp-content-dialog-view"};
};

} // namespace tailgate::uwp
