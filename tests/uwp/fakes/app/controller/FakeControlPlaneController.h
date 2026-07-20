#pragma once

#include <cstddef>

#include "app/controller/ControlPlaneController.h"

namespace tailgate::uwp::tests
{

class FakeControlPlaneController final : public ControlPlaneController
{
public:
    [[nodiscard]] const ControlPlaneState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] ControlPlaneState& GetState() noexcept
    {
        return m_state;
    }

    void Logout(std::optional<protocol::Bytes32>, std::optional<protocol::Bytes32>) override
    {
        ++LogoutCount;
    }

    std::size_t LogoutCount = 0;

private:
    ControlPlaneState m_state;
};

} // namespace tailgate::uwp::tests
