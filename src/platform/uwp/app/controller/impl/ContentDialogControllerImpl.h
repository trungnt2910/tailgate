#pragma once

#include "app/controller/ContentDialogController.h"

namespace tailgate::uwp
{

class ContentDialogControllerImpl final : public ContentDialogController
{
public:
    [[nodiscard]] const ContentDialogState& GetState() const noexcept override;
    void ShowDialog(ContentDialogControllerState dialog) override;
    void HideDialog(ContentDialogControllerState dialog) override;

private:
    ContentDialogState m_state;
};

} // namespace tailgate::uwp
