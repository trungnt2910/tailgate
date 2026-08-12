#pragma once

#include <cstddef>

#include "app/view/NodeAuthorizationDialogView.h"
#include "app/view/PingDialogView.h"
#include "app/view/SignInDialogView.h"

#include "IdlingRegistry.h"

namespace tailgate::uwp::tests
{

template <typename Interface>
class FakeDialogView : public Interface, public IIdlingResource
{
public:
    explicit FakeDialogView(IdlingRegistry& idlingRegistry) : m_idlingRegistry(idlingRegistry)
    {
        const controls::TextBlock content;
        content.Text(L"Fake dialog dependency");
        m_dialog.Content(content);
        m_dialogOpened = m_dialog.Opened(
            [this](const auto&, const auto&)
            {
                m_idle = true;
            });
        m_dialogClosing = m_dialog.Closing(
            [this](const auto&, const auto&)
            {
                m_idle = false;
            });
        m_idlingRegistry.Register(*this);
    }

    ~FakeDialogView() override
    {
        m_idlingRegistry.Deregister(*this);
    }

    [[nodiscard]] controls::ContentDialog Dialog() const override
    {
        return m_dialog;
    }

    void OnOpening() noexcept override
    {
        m_idle = false;
    }

    void OnClosed(controls::ContentDialogResult result) override
    {
        ++OnClosedCount;
        LastResult = result;
        m_idle = true;
    }

    [[nodiscard]] bool IsIdle() const noexcept override
    {
        return m_idle;
    }

    inline static std::size_t OnClosedCount = 0;
    inline static controls::ContentDialogResult LastResult = controls::ContentDialogResult::None;

private:
    void Render() override
    {
    }

    void OnStateChange(const std::string&) override
    {
    }

    IdlingRegistry& m_idlingRegistry;
    controls::ContentDialog m_dialog;
    winrt::event_token m_dialogOpened{};
    winrt::event_token m_dialogClosing{};
    bool m_idle = true;
};

using FakeNodeAuthorizationDialogView = FakeDialogView<NodeAuthorizationDialogView>;
using FakePingDialogView = FakeDialogView<PingDialogView>;
using FakeSignInDialogView = FakeDialogView<SignInDialogView>;

} // namespace tailgate::uwp::tests
