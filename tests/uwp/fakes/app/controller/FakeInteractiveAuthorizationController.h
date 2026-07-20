#pragma once

#include <cstddef>
#include <optional>

#include "app/controller/InteractiveAuthorizationController.h"

namespace tailgate::uwp::tests
{

class FakeInteractiveAuthorizationController final : public InteractiveAuthorizationController
{
public:
    [[nodiscard]] const InteractiveAuthorizationState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] InteractiveAuthorizationState& GetState() noexcept
    {
        return m_state;
    }

    void Listen(const winrt::hstring& server) override
    {
        ListenArgument = server;
    }

    void Stop() override
    {
        ++StopCount;
    }

    void Cancel() override
    {
        ++CancelCount;
    }

    std::optional<winrt::hstring> ListenArgument;
    std::size_t StopCount = 0;
    std::size_t CancelCount = 0;

private:
    InteractiveAuthorizationState m_state;
};

} // namespace tailgate::uwp::tests
