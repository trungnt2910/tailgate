#pragma once

#include <chrono>
#include <string>

#include <tailgate/control/client/ControlClient.h>

#include "State.h"

namespace tailgate::linux_frontend
{

class Registration final : public tailgate::control::client::RegistrationHandler
{
public:
    Registration(std::string& pendingAuthKey,
                 std::string& fallbackAuthKey,
                 std::string& pendingAuthorizationUrl,
                 DaemonStatus& status);

    void Accepted();
    void StateChanged(const tailgate::control::client::RegistrationResult& state) override;
    bool WaitForRetry(std::chrono::milliseconds delay) override;

private:
    std::string& m_pendingAuthKey;
    std::string& m_fallbackAuthKey;
    std::string& m_pendingAuthorizationUrl;
    DaemonStatus& m_status;
};

} // namespace tailgate::linux_frontend
