#pragma once

#include <tailgate/cli/Arguments.h>

#include "app/model/SetOptionsState.h"

namespace tailgate::uwp
{

class SetOptionsController
{
public:
    virtual ~SetOptionsController() = default;

    [[nodiscard]] virtual const SetOptionsState& GetState() const noexcept = 0;
    virtual void Apply(const tailgate::cli::SetOptions& options) = 0;
};

} // namespace tailgate::uwp
