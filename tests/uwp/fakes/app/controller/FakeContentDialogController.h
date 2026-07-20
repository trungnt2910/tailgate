#pragma once

#include <cstddef>

#include "app/controller/ContentDialogController.h"

namespace tailgate::uwp::tests
{

class FakeContentDialogController final : public ContentDialogController
{
public:
    using Interface = ContentDialogController;

    [[nodiscard]] const ContentDialogState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] ContentDialogState& GetState() noexcept
    {
        return m_state;
    }

    void ShowDialog(ContentDialogControllerState dialog) override
    {
        ++ShowCount;
        m_state.Current(dialog);
    }

    void HideDialog(ContentDialogControllerState dialog) override
    {
        ++HideCount;
        if (m_state.Current() == dialog)
        {
            m_state.Current(ContentDialogControllerState::None);
        }
    }

    std::size_t ShowCount = 0;
    std::size_t HideCount = 0;

private:
    ContentDialogState m_state;
};

} // namespace tailgate::uwp::tests
