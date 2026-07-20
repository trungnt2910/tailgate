#pragma once

#include <cstddef>

#include "app/view/NodeAuthorizationDialogView.h"
#include "app/view/PingDialogView.h"
#include "app/view/SignInDialogView.h"

namespace tailgate::uwp::tests
{

template <typename Interface>
class FakeDialogView : public Interface
{
public:
    FakeDialogView()
    {
        const controls::TextBlock content;
        content.Text(L"Fake dialog dependency");
        m_dialog.Content(content);
    }

    [[nodiscard]] controls::ContentDialog Dialog() const override
    {
        return m_dialog;
    }

    void OnClosed(controls::ContentDialogResult result) override
    {
        ++OnClosedCount;
        LastResult = result;
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

    controls::ContentDialog m_dialog;
};

using FakeNodeAuthorizationDialogView = FakeDialogView<NodeAuthorizationDialogView>;
using FakePingDialogView = FakeDialogView<PingDialogView>;
using FakeSignInDialogView = FakeDialogView<SignInDialogView>;

} // namespace tailgate::uwp::tests
