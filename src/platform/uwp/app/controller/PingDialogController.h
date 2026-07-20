#pragma once

#include "app/model/PingDialogState.h"
#include "common/UwpAliases.h"

namespace tailgate::uwp
{

class PingDialogController
{
public:
    virtual ~PingDialogController() = default;

    [[nodiscard]] virtual const PingDialogState& GetState() const noexcept = 0;
    virtual void Show(const winrt::hstring& deviceName,
                      const winrt::hstring& address,
                      const winrt::hstring& selfAddress) = 0;
    virtual void Hide() = 0;
    virtual void OnClosed() = 0;
};

} // namespace tailgate::uwp
