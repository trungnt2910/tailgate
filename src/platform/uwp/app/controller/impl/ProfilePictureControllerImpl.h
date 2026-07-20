#pragma once

#include <tailgate/Logger.h>

#include "common/UwpFormat.h"

#include "common/UwpFireAndForget.h"

#include "app/controller/ProfilePictureController.h"

namespace tailgate::uwp
{

class SettingsController;

class ProfilePictureControllerImpl final : public ProfilePictureController
{
public:
    explicit ProfilePictureControllerImpl(SettingsController& settingsController);

    [[nodiscard]] const ProfilePictureState& GetState() const noexcept override;
    void Load() override;
    void Clear() override;

private:
    FireAndForget LoadAsync();

    SettingsController& m_settingsController;
    ProfilePictureState m_state;
    bool m_loading = false;
    bool m_applied = false;
    Logger m_logger{"uwp-profile-picture-ctrl"};
};

} // namespace tailgate::uwp
