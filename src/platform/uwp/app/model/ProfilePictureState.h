#pragma once

#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

class ProfilePictureState final : public ObservableState<ProfilePictureState>
{
    TAILGATE_PROPERTY(Image, media::ImageSource);
};

} // namespace tailgate::uwp
