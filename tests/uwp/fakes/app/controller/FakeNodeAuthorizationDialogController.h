#pragma once

#include <cstddef>

#include "app/controller/NodeAuthorizationDialogController.h"

namespace tailgate::uwp::tests
{

class FakeNodeAuthorizationDialogController final : public NodeAuthorizationDialogController
{
public:
    [[nodiscard]] const NodeAuthorizationDialogState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] NodeAuthorizationDialogState& GetState() noexcept
    {
        return m_state;
    }

    void Show(const winrt::hstring&, bool) override
    {
        ++ShowCount;
    }

    void Hide() override
    {
        ++HideCount;
    }

    void OnPrimaryButtonClick() override
    {
        ++PrimaryCount;
    }

    void OnCloseButtonClick() override
    {
        ++CloseCount;
    }

    std::size_t ShowCount = 0;
    std::size_t HideCount = 0;
    std::size_t PrimaryCount = 0;
    std::size_t CloseCount = 0;

private:
    NodeAuthorizationDialogState m_state;
};

} // namespace tailgate::uwp::tests
