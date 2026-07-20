#pragma once

#include "app/model/ContentDialogState.h"

namespace tailgate::uwp
{

class ContentDialogController
{
public:
    virtual ~ContentDialogController() = default;

    [[nodiscard]] virtual const ContentDialogState& GetState() const noexcept = 0;
    virtual void ShowDialog(ContentDialogControllerState dialog) = 0;
    virtual void HideDialog(ContentDialogControllerState dialog) = 0;
};

} // namespace tailgate::uwp
