#pragma once

#include <optional>

#include "common/UwpError.h"

#include "app/model/SessionState.h"

namespace tailgate::uwp
{

class SessionController
{
public:
    virtual ~SessionController() = default;

    [[nodiscard]] virtual const SessionState& GetState() const noexcept = 0;
    virtual void
    Connect(winrt::hstring tailgateServer,
            winrt::hstring authKey,
            bool showDialogOnFailure = false,
            bool restartConnectedProfile = false,
            std::optional<ConnectionSettingsSnapshot> rollbackSettings = std::nullopt) = 0;
    virtual void ConnectStoredOrRequestSignIn() = 0;
    virtual void Disconnect() = 0;
    virtual void Logout() = 0;
    virtual void Refresh() = 0;
    virtual void CancelActiveConnectionAttempt() = 0;
    virtual void BeginExitNodeChange() = 0;
    virtual void FinishExitNodeChange(std::optional<UwpError::Code> error) = 0;
};

} // namespace tailgate::uwp
