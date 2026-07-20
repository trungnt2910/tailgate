#pragma once

#include "app/model/PackageState.h"

namespace tailgate::uwp
{

class PackageController
{
public:
    virtual ~PackageController() = default;

    [[nodiscard]] virtual const PackageState& GetState() const noexcept = 0;
};

} // namespace tailgate::uwp
