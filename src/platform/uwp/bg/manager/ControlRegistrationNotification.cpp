#include "ControlRegistrationNotification.h"

#include <utility>

namespace tailgate::uwp::bg::manager
{

std::optional<ForegroundConnectionNotification>
BuildAuthenticationNotification(const tailgate::control::client::RegistrationResult& registration,
                                std::string tailgateServer)
{
    switch (registration.State)
    {
    case tailgate::control::client::RegistrationState::LoginRequired:
        return ForegroundConnectionNotification{
            .Kind = ForegroundConnectionKind::LoginRequired,
            .Url = registration.AuthorizationUrl,
            .TailgateServer = std::move(tailgateServer),
        };
    case tailgate::control::client::RegistrationState::MachineApprovalRequired:
        return ForegroundConnectionNotification{
            .Kind = ForegroundConnectionKind::MachineApprovalRequired,
            .Url = registration.ApprovalUrl,
            .TailgateServer = std::move(tailgateServer),
        };
    case tailgate::control::client::RegistrationState::Complete:
        return std::nullopt;
    }
    return std::nullopt;
}

} // namespace tailgate::uwp::bg::manager
