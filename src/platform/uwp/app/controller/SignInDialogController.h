#pragma once

#include <optional>

#include "common/UwpAliases.h"
#include "common/UwpError.h"

#include "app/model/SignInDialogState.h"

namespace tailgate::uwp
{

class SignInDialogController
{
public:
    virtual ~SignInDialogController() = default;

    [[nodiscard]] virtual const SignInDialogState& GetState() const noexcept = 0;
    virtual void Show(const winrt::hstring& tailgateServer,
                      const winrt::hstring& authKey,
                      const winrt::hstring& hostname,
                      std::optional<UwpError::Code> error) = 0;
    virtual void Hide() = 0;
    virtual void OnClosed(controls::ContentDialogResult result) = 0;

    virtual void OnTailgateServerChanged(const winrt::hstring& value) = 0;
    virtual void OnAuthKeyChanged(const winrt::hstring& value) = 0;
    virtual void OnHostnameChanged(const winrt::hstring& value) = 0;
    virtual void OnAdvancedClicked() = 0;
    virtual void OnAdvancedPointerEntered() = 0;
    virtual void OnAdvancedPointerExited() = 0;
    virtual void OnPrimaryButtonClick() = 0;
};

} // namespace tailgate::uwp
