#include "BackgroundTaskLifetime.h"

#include <tailgate/base/Logger.h>

#include "common/UwpFormat.h"

namespace tailgate::uwp::bg
{

BackgroundTaskLifetime::BackgroundTaskLifetime(
    const winrt::Windows::ApplicationModel::Background::IBackgroundTaskInstance& task)
    : m_deferral(task.GetDeferral())
{
}

BackgroundTaskLifetime::~BackgroundTaskLifetime()
{
    try
    {
        m_deferral.Complete();
    }
    catch (...)
    {
        base::Logger("uwp-background-task")
            .LogWarning("task deferral completion failed: {}", winrt::to_message());
    }
}

} // namespace tailgate::uwp::bg
