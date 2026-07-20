#pragma once

#include <cstdint>
#include <optional>

#include "common/UwpError.h"

#include "app/model/ObservableState.h"
#include "app/model/SettingsState.h"

namespace tailgate::uwp
{

enum class SessionActivity
{
    Idle,
    Checking,
    Starting,
    Stopping,
    LoggingOut,
    ChangingSettings,
};

struct PendingConnectRequest
{
    bool operator==(const PendingConnectRequest&) const = default;

    winrt::hstring TailgateServer;
    winrt::hstring AuthKey;
    bool ShowDialogOnFailure = false;
    bool RestartConnectedProfile = false;
    std::optional<ConnectionSettingsSnapshot> RollbackSettings;
};

class SessionState final : public ObservableState<SessionState>
{
    TAILGATE_PROPERTY(Connected, bool);
    TAILGATE_PROPERTY(Busy, bool);
    TAILGATE_PROPERTY(ConnectionOperationActive, bool);
    TAILGATE_PROPERTY(Activity, SessionActivity);
    TAILGATE_PROPERTY(Error, std::optional<UwpError::Code>);
    TAILGATE_PROPERTY(PendingConnect, std::optional<PendingConnectRequest>);
    TAILGATE_PROPERTY(SignInRequest, std::uint64_t);
};

} // namespace tailgate::uwp
