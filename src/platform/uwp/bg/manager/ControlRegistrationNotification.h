#pragma once

#include <optional>
#include <string>

#include <tailgate/control/client/ControlClient.h>

#include "manager/SessionManager.h"

namespace tailgate::uwp::bg::manager
{

[[nodiscard]] std::optional<ForegroundConnectionNotification>
BuildAuthenticationNotification(const tailgate::control::client::RegistrationResult& registration,
                                std::string tailgateServer);

} // namespace tailgate::uwp::bg::manager
