#pragma once

#include "app/controller/ContentDialogController.h"
#include "app/controller/NodeAuthorizationDialogController.h"

namespace tailgate::uwp
{

class NodeAuthorizationDialogControllerImpl final : public NodeAuthorizationDialogController
{
public:
    explicit NodeAuthorizationDialogControllerImpl(ContentDialogController& dialogController);

    [[nodiscard]] const NodeAuthorizationDialogState& GetState() const noexcept override;
    void Show(const winrt::hstring& authUrl, bool machineApproval) override;
    void Hide() override;
    void OnPrimaryButtonClick() override;
    void OnCloseButtonClick() override;

private:
    ContentDialogController& m_dialogController;
    NodeAuthorizationDialogState m_state;
};

} // namespace tailgate::uwp
