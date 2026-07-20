#pragma once

#include <cstddef>
#include <optional>
#include <utility>

#include "app/controller/SessionController.h"

namespace tailgate::uwp::tests
{

struct ConnectCall final
{
    winrt::hstring tailgateServer;
    winrt::hstring authKey;
    bool showDialogOnFailure = false;
    bool restartConnectedProfile = false;
    std::optional<ConnectionSettingsSnapshot> rollbackSettings;
};

class FakeSessionController final : public SessionController
{
public:
    using Interface = SessionController;

    [[nodiscard]] const SessionState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] SessionState& GetState() noexcept
    {
        return m_state;
    }

    void Connect(winrt::hstring tailgateServer,
                 winrt::hstring authKey,
                 bool showDialogOnFailure,
                 bool restartConnectedProfile,
                 std::optional<ConnectionSettingsSnapshot> rollbackSettings) override
    {
        LastConnect = ConnectCall{
            .tailgateServer = std::move(tailgateServer),
            .authKey = std::move(authKey),
            .showDialogOnFailure = showDialogOnFailure,
            .restartConnectedProfile = restartConnectedProfile,
            .rollbackSettings = std::move(rollbackSettings),
        };
    }

    void ConnectStoredOrRequestSignIn() override
    {
        ++ConnectStoredOrRequestSignInCount;
    }

    void Disconnect() override
    {
        ++DisconnectCount;
    }

    void Logout() override
    {
        ++LogoutCount;
    }

    void Refresh() override
    {
        ++RefreshCount;
    }

    void CancelActiveConnectionAttempt() override
    {
        ++CancelActiveConnectionAttemptCount;
    }

    void BeginExitNodeChange() override
    {
        ++BeginExitNodeChangeCount;
    }

    void FinishExitNodeChange(std::optional<UwpError::Code> error) override
    {
        FinishExitNodeChangeError = error;
    }

    std::optional<ConnectCall> LastConnect;
    std::optional<std::optional<UwpError::Code>> FinishExitNodeChangeError;
    std::size_t ConnectStoredOrRequestSignInCount = 0;
    std::size_t DisconnectCount = 0;
    std::size_t LogoutCount = 0;
    std::size_t RefreshCount = 0;
    std::size_t CancelActiveConnectionAttemptCount = 0;
    std::size_t BeginExitNodeChangeCount = 0;

private:
    SessionState m_state;
};

} // namespace tailgate::uwp::tests
