#pragma once

#include <cstddef>
#include <optional>
#include <utility>

#include "app/controller/PingDialogController.h"

namespace tailgate::uwp::tests
{

struct PingDialogShowCall final
{
    winrt::hstring deviceName;
    winrt::hstring address;
    winrt::hstring selfAddress;
};

class FakePingDialogController final : public PingDialogController
{
public:
    [[nodiscard]] const PingDialogState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] PingDialogState& GetState() noexcept
    {
        return m_state;
    }

    void Show(const winrt::hstring& deviceName,
              const winrt::hstring& address,
              const winrt::hstring& selfAddress) override
    {
        ++ShowCount;
        LastShow = PingDialogShowCall{
            .deviceName = deviceName,
            .address = address,
            .selfAddress = selfAddress,
        };
    }

    void Hide() override
    {
        ++HideCount;
    }

    void OnClosed() override
    {
        ++OnClosedCount;
    }

    std::size_t ShowCount = 0;
    std::size_t HideCount = 0;
    std::size_t OnClosedCount = 0;
    std::optional<PingDialogShowCall> LastShow;

private:
    PingDialogState m_state;
};

} // namespace tailgate::uwp::tests
