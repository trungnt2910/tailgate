#pragma once

#include "app/controller/PackageController.h"

namespace tailgate::uwp::tests
{

class FakePackageController final : public PackageController
{
public:
    [[nodiscard]] const PackageState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] PackageState& GetState() noexcept
    {
        return m_state;
    }

private:
    PackageState m_state;
};

} // namespace tailgate::uwp::tests
