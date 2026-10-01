#pragma once

#include <winrt/Windows.ApplicationModel.Background.h>

namespace tailgate::uwp::bg
{

// One dispatch owns one deferral. Complete it when ProcessEventAsync work returns,
// including exception paths; the connected channel has an independent lifetime.
class BackgroundTaskLifetime final
{
public:
    explicit BackgroundTaskLifetime(
        const winrt::Windows::ApplicationModel::Background::IBackgroundTaskInstance& task);
    ~BackgroundTaskLifetime();
    BackgroundTaskLifetime(const BackgroundTaskLifetime&) = delete;
    BackgroundTaskLifetime& operator=(const BackgroundTaskLifetime&) = delete;

private:
    winrt::Windows::ApplicationModel::Background::BackgroundTaskDeferral m_deferral;
};

} // namespace tailgate::uwp::bg
