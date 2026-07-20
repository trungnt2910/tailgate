#pragma once

#include <cstdint>
#include <optional>

#include "app/controller/TailgateRelayController.h"

namespace tailgate::uwp::tests
{

struct PreflightCall final
{
    std::uint64_t operationId = 0;
    winrt::hstring tailgateServer;
};

class FakeTailgateRelayController final : public TailgateRelayController
{
public:
    [[nodiscard]] const TailgateRelayState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] TailgateRelayState& GetState() noexcept
    {
        return m_state;
    }

    void Preflight(std::uint64_t operationId, const winrt::hstring& server) override
    {
        LastPreflight = PreflightCall{.operationId = operationId, .tailgateServer = server};
    }

    std::optional<PreflightCall> LastPreflight;

private:
    TailgateRelayState m_state;
};

} // namespace tailgate::uwp::tests
