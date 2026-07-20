#pragma once

#include "app/controller/PackageController.h"

namespace tailgate::uwp
{

class PackageControllerImpl final : public PackageController
{
public:
    PackageControllerImpl();

    [[nodiscard]] const PackageState& GetState() const noexcept override;

private:
    PackageState m_state;
};

} // namespace tailgate::uwp
