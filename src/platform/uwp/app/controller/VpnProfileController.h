#pragma once

#include "app/model/VpnProfileState.h"

namespace tailgate::uwp
{

class VpnProfileController
{
public:
    virtual ~VpnProfileController() = default;

    [[nodiscard]] virtual const VpnProfileState& GetState() const noexcept = 0;
    virtual void Connect(winrt::hstring tailgateServer,
                         winrt::hstring authKey,
                         bool restartConnectedProfile) = 0;
    virtual void CancelConnect() = 0;
    virtual void Disconnect() = 0;
    virtual void Logout() = 0;
    virtual void DiscardProfile() = 0;
    virtual void Refresh() = 0;
};

} // namespace tailgate::uwp
