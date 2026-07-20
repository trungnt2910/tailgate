#pragma once

#include <cstddef>
#include <optional>

#include "app/controller/SettingsController.h"

namespace tailgate::uwp::tests
{

struct SetExitNodeCall final
{
    winrt::hstring exitNode;
    bool preserveSelection = false;
};

class FakeSettingsController final : public SettingsController
{
public:
    using Interface = SettingsController;

    [[nodiscard]] const SettingsState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] SettingsState& GetState() noexcept
    {
        return m_state;
    }

    void Reload() override
    {
        ++ReloadCount;
    }

    void Clear() override
    {
        ++ClearCount;
    }

    void SetHostname(const winrt::hstring& hostname) override
    {
        SetHostnameArgument = hostname;
        m_state.Hostname(hostname);
    }

    void SetTailgateServer(const winrt::hstring& tailgateServer) override
    {
        SetTailgateServerArgument = tailgateServer;
        m_state.TailgateServer(tailgateServer);
    }

    void SetAuthentication(const winrt::hstring& tailgateServer,
                           const winrt::hstring& authKey) override
    {
        SetAuthenticationTailgateServer = tailgateServer;
        SetAuthenticationAuthKey = authKey;
    }

    void SetExitNode(const winrt::hstring& exitNode, bool preserveSelection) override
    {
        LastSetExitNode = SetExitNodeCall{
            .exitNode = exitNode,
            .preserveSelection = preserveSelection,
        };
        m_state.ExitNode(exitNode);
    }

    void SetCachedProfilePictureUrl(const winrt::hstring& url) override
    {
        SetCachedProfilePictureUrlArgument = url;
    }

    void ClearCachedProfilePictureUrl() override
    {
        ++ClearCachedProfilePictureUrlCount;
    }

    void RestoreConnectionSettings(const ConnectionSettingsSnapshot& settings) override
    {
        RestoreConnectionSettingsArgument = settings;
    }

    std::optional<winrt::hstring> SetHostnameArgument;
    std::optional<winrt::hstring> SetTailgateServerArgument;
    std::optional<winrt::hstring> SetAuthenticationTailgateServer;
    std::optional<winrt::hstring> SetAuthenticationAuthKey;
    std::optional<SetExitNodeCall> LastSetExitNode;
    std::optional<winrt::hstring> SetCachedProfilePictureUrlArgument;
    std::optional<ConnectionSettingsSnapshot> RestoreConnectionSettingsArgument;
    std::size_t ReloadCount = 0;
    std::size_t ClearCount = 0;
    std::size_t ClearCachedProfilePictureUrlCount = 0;

private:
    SettingsState m_state;
};

} // namespace tailgate::uwp::tests
