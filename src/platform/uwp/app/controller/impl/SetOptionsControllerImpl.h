#pragma once

#include <tailgate/base/Logger.h>

#include "common/UwpFormat.h"

#include "app/controller/SetOptionsController.h"

namespace tailgate::uwp
{

class ExitNodeController;
class SessionController;
class SettingsController;

class SetOptionsControllerImpl final : public SetOptionsController
{
public:
    SetOptionsControllerImpl(ExitNodeController& exitNodeController,
                             SessionController& sessionController,
                             SettingsController& settingsController);

    [[nodiscard]] const SetOptionsState& GetState() const noexcept override;
    void Apply(const tailgate::cli::SetOptions& options) override;

private:
    ExitNodeController& m_exitNodeController;
    SessionController& m_sessionController;
    SettingsController& m_settingsController;
    SetOptionsState m_state;
    tailgate::base::Logger m_logger{"uwp-set-options-ctrl"};
};

} // namespace tailgate::uwp
