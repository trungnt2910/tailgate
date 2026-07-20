#pragma once

#include <winrt/Windows.UI.Core.h>

#include <tailgate/Logger.h>

#include "common/UwpFormat.h"

#include "app/controller/SettingsController.h"

namespace tailgate::uwp
{

class SettingsControllerImpl final : public SettingsController
{
public:
    SettingsControllerImpl();
    ~SettingsControllerImpl() override;

    [[nodiscard]] const SettingsState& GetState() const noexcept override;
    void Reload() override;
    void Clear() override;
    void SetHostname(const winrt::hstring& hostname) override;
    void SetTailgateServer(const winrt::hstring& tailgateServer) override;
    void SetAuthentication(const winrt::hstring& tailgateServer,
                           const winrt::hstring& authKey) override;
    void SetExitNode(const winrt::hstring& exitNode, bool preserveSelection) override;
    void SetCachedProfilePictureUrl(const winrt::hstring& url) override;
    void ClearCachedProfilePictureUrl() override;
    void RestoreConnectionSettings(const ConnectionSettingsSnapshot& settings) override;

private:
    void EnsureStateWatchStarted();

    winrt::Windows::UI::Core::CoreDispatcher m_dispatcher{nullptr};
    winrt::event_token m_dataChangedToken{};
    bool m_stateWatchStarted = false;
    SettingsState m_state;
    Logger m_logger{"uwp-settings-ctrl"};
};

} // namespace tailgate::uwp
