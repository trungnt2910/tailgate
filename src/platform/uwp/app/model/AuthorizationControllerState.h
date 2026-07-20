#pragma once

#include <optional>

#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

struct AuthorizationCache
{
    bool operator==(const AuthorizationCache&) const = default;

    winrt::hstring Url;
    winrt::hstring TailgateServer;
    winrt::hstring AuthKey;
    winrt::hstring Hostname;
    bool MachineApproval = false;
};

class AuthorizationControllerState final : public ObservableState<AuthorizationControllerState>
{
    TAILGATE_PROPERTY(PendingTailgateServer, winrt::hstring);
    TAILGATE_PROPERTY(PendingAuthKey, winrt::hstring);
    TAILGATE_PROPERTY(PendingHostname, std::optional<winrt::hstring>);
    TAILGATE_PROPERTY(Authorization, std::optional<AuthorizationCache>);
    TAILGATE_PROPERTY(MatchedAuthorization, std::optional<AuthorizationCache>);
    TAILGATE_PROPERTY(PromptUrl, winrt::hstring);
    TAILGATE_PROPERTY(MachineApproval, bool);
};

} // namespace tailgate::uwp
