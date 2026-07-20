#pragma once

#include "app/model/NodeAuthorizationDialogState.h"
#include "common/UwpAliases.h"

namespace tailgate::uwp
{

class NodeAuthorizationDialogController
{
public:
    virtual ~NodeAuthorizationDialogController() = default;

    [[nodiscard]] virtual const NodeAuthorizationDialogState& GetState() const noexcept = 0;
    virtual void Show(const winrt::hstring& authUrl, bool machineApproval) = 0;
    virtual void Hide() = 0;
    virtual void OnPrimaryButtonClick() = 0;
    virtual void OnCloseButtonClick() = 0;
};

} // namespace tailgate::uwp
