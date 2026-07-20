#pragma once

#include <optional>

#include "common/UwpError.h"

#include "app/model/ObservableState.h"

namespace tailgate::uwp
{

class SignInDialogState final : public ObservableState<SignInDialogState>
{
public:
    SignInDialogState() = default;

    TAILGATE_PROPERTY(TailgateServer, winrt::hstring);
    TAILGATE_PROPERTY(AuthKey, winrt::hstring);
    TAILGATE_PROPERTY(Hostname, winrt::hstring);
    TAILGATE_PROPERTY(Error, std::optional<UwpError::Code>);
    TAILGATE_PROPERTY(AdvancedExpanded, bool);
    TAILGATE_PROPERTY(AdvancedHovered, bool);
    TAILGATE_PROPERTY(ValidationErrorVisible, bool);
    TAILGATE_PROPERTY(Accepted, bool);
};

} // namespace tailgate::uwp
