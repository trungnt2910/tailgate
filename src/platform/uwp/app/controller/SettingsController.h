#pragma once

#include "app/model/SettingsState.h"

namespace tailgate::uwp
{

class SettingsController
{
public:
    virtual ~SettingsController() = default;

    [[nodiscard]] virtual const SettingsState& GetState() const noexcept = 0;
    virtual void Reload() = 0;
    virtual void Clear() = 0;
    virtual void SetHostname(const winrt::hstring& hostname) = 0;
    virtual void SetTailgateServer(const winrt::hstring& tailgateServer) = 0;
    virtual void SetAuthentication(const winrt::hstring& tailgateServer,
                                   const winrt::hstring& authKey) = 0;
    virtual void SetExitNode(const winrt::hstring& exitNode, bool preserveSelection) = 0;
    virtual void SetCachedProfilePictureUrl(const winrt::hstring& url) = 0;
    virtual void ClearCachedProfilePictureUrl() = 0;
    virtual void RestoreConnectionSettings(const ConnectionSettingsSnapshot& settings) = 0;
};

} // namespace tailgate::uwp
