#pragma once

#include "app/model/ProfilePictureState.h"

namespace tailgate::uwp
{

class ProfilePictureController
{
public:
    virtual ~ProfilePictureController() = default;

    [[nodiscard]] virtual const ProfilePictureState& GetState() const noexcept = 0;
    virtual void Load() = 0;
    virtual void Clear() = 0;
};

} // namespace tailgate::uwp
