#pragma once

#include "app/controller/ModeController.h"
#include "app/controller/ModeRpcController.h"
#include "app/controller/SessionController.h"
#include "app/controller/SettingsController.h"

namespace tailgate::uwp
{

class ModeControllerImpl final : public ModeController
{
public:
    ModeControllerImpl(ModeRpcController& rpc,
                       SessionController& session,
                       SettingsController& settings);
    [[nodiscard]] const ModeState& GetState() const noexcept override;
    void SetRelay(const winrt::hstring& relayUrl) override;

private:
    void Receive();
    ModeRpcController& m_rpc;
    SessionController& m_session;
    SettingsController& m_settings;
    ModeState m_state;
    StateEventRegistration m_registration;
};

} // namespace tailgate::uwp
