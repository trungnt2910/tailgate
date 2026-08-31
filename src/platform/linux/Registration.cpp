#include "Registration.h"

#include <chrono>
#include <format>
#include <optional>

#include <tailgate/base/Logging.h>

#include "Lifecycle.h"

namespace tailgate::linux_frontend
{

Registration::Registration(std::string& pendingAuthKey,
                           std::string& fallbackAuthKey,
                           std::string& pendingAuthorizationUrl,
                           DaemonStatus& status)
    : m_pendingAuthKey(pendingAuthKey),
      m_fallbackAuthKey(fallbackAuthKey),
      m_pendingAuthorizationUrl(pendingAuthorizationUrl),
      m_status(status)
{
}

void Registration::Accepted()
{
    m_pendingAuthKey.clear();
    m_fallbackAuthKey.clear();
    m_pendingAuthorizationUrl.clear();
    m_status.AuthorizationUrl.clear();
    m_status.Error.clear();
    const std::optional<IdentityState> current = ReadIdentity();
    if (current && !current->RegistrationComplete)
    {
        IdentityState completed = *current;
        completed.RegistrationComplete = true;
        WriteIdentity(completed);
    }
}

void Registration::StateChanged(const tailgate::control::client::RegistrationResult& registration)
{
    const bool loginRequired =
        registration.State == tailgate::control::client::RegistrationState::LoginRequired;
    m_pendingAuthorizationUrl = loginRequired ? registration.AuthorizationUrl : std::string{};
    m_status.BackendState = loginRequired ? "NeedsLogin" : "NeedsMachineAuth";
    m_status.Online = false;
    m_status.AuthorizationUrl =
        loginRequired ? registration.AuthorizationUrl : registration.ApprovalUrl;
    m_status.Error.clear();
    WriteDaemonStatus(m_status);
    tailgate::base::Log(
        tailgate::base::LogLevel::Info,
        "control",
        loginRequired
            ? std::format("waiting for interactive login code={}",
                          registration.AuthorizationCode.empty() ? "unavailable"
                                                                 : registration.AuthorizationCode)
            : std::format("waiting for machine approval url={}", registration.ApprovalUrl));
}

bool Registration::WaitForRetry(std::chrono::milliseconds delay)
{
    return Lifecycle::WaitForChange(delay);
}

} // namespace tailgate::linux_frontend
