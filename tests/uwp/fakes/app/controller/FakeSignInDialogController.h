#pragma once

#include <cstddef>
#include <optional>

#include "app/controller/SignInDialogController.h"

namespace tailgate::uwp::tests
{

class FakeSignInDialogController final : public SignInDialogController
{
public:
    using Interface = SignInDialogController;

    [[nodiscard]] const SignInDialogState& GetState() const noexcept override
    {
        return m_state;
    }

    [[nodiscard]] SignInDialogState& GetState() noexcept
    {
        return m_state;
    }

    void Show(const winrt::hstring& tailgateServer,
              const winrt::hstring& authKey,
              const winrt::hstring& hostname,
              std::optional<UwpError::Code> error) override
    {
        ++ShowCount;
        m_state.TailgateServer(tailgateServer);
        m_state.AuthKey(authKey);
        m_state.Hostname(hostname);
        m_state.Error(error);
    }

    void Hide() override
    {
        ++HideCount;
    }

    void OnClosed(controls::ContentDialogResult result) override
    {
        OnClosedArgument = result;
    }

    void OnTailgateServerChanged(const winrt::hstring& value) override
    {
        m_state.TailgateServer(value);
    }

    void OnAuthKeyChanged(const winrt::hstring& value) override
    {
        m_state.AuthKey(value);
    }

    void OnHostnameChanged(const winrt::hstring& value) override
    {
        m_state.Hostname(value);
    }

    void OnAdvancedClicked() override
    {
        ++OnAdvancedClickedCount;
    }

    void OnAdvancedPointerEntered() override
    {
        ++OnAdvancedPointerEnteredCount;
    }

    void OnAdvancedPointerExited() override
    {
        ++OnAdvancedPointerExitedCount;
    }

    void OnPrimaryButtonClick() override
    {
        ++OnPrimaryButtonClickCount;
    }

    std::optional<controls::ContentDialogResult> OnClosedArgument;
    std::size_t ShowCount = 0;
    std::size_t HideCount = 0;
    std::size_t OnAdvancedClickedCount = 0;
    std::size_t OnAdvancedPointerEnteredCount = 0;
    std::size_t OnAdvancedPointerExitedCount = 0;
    std::size_t OnPrimaryButtonClickCount = 0;

private:
    SignInDialogState m_state;
};

} // namespace tailgate::uwp::tests
