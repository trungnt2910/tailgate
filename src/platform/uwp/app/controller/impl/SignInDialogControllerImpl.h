#pragma once

#include "app/controller/ContentDialogController.h"
#include "app/controller/SignInDialogController.h"

namespace tailgate::uwp
{

class SignInDialogControllerImpl final : public SignInDialogController
{
public:
    explicit SignInDialogControllerImpl(ContentDialogController& dialogController);

    [[nodiscard]] const SignInDialogState& GetState() const noexcept override;
    void Show(const winrt::hstring& tailgateServer,
              const winrt::hstring& authKey,
              const winrt::hstring& hostname,
              std::optional<UwpError::Code> error) override;
    void Hide() override;
    void OnClosed(controls::ContentDialogResult result) override;

    void OnTailgateServerChanged(const winrt::hstring& value) override;
    void OnAuthKeyChanged(const winrt::hstring& value) override;
    void OnHostnameChanged(const winrt::hstring& value) override;
    void OnAdvancedClicked() override;
    void OnAdvancedPointerEntered() override;
    void OnAdvancedPointerExited() override;
    void OnPrimaryButtonClick() override;

private:
    ContentDialogController& m_dialogController;
    SignInDialogState m_state;
};

} // namespace tailgate::uwp
