#pragma once
#include "app/controller/ModeController.h"

namespace tailgate::uwp::tests
{

class FakeModeController final : public ModeController
{
public:
    const ModeState& GetState() const noexcept override
    {
        return State;
    }

    ModeState& GetState() noexcept
    {
        return State;
    }

    void SetRelay(const winrt::hstring& relay) override
    {
        LastRelay = relay;
    }

    ModeState State;
    std::optional<winrt::hstring> LastRelay;
};

} // namespace tailgate::uwp::tests
