#pragma once

#include <cstddef>

#include "app/controller/SetOptionsController.h"

namespace tailgate::uwp::tests
{

class FakeSetOptionsController final : public SetOptionsController
{
public:
    [[nodiscard]] const SetOptionsState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] SetOptionsState& GetState() noexcept
    {
        return m_state;
    }

    void Apply(const tailgate::cli::SetOptions&) override
    {
        ++ApplyCount;
    }

    std::size_t ApplyCount = 0;

private:
    SetOptionsState m_state;
};

} // namespace tailgate::uwp::tests
