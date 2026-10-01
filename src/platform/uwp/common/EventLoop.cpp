#include "EventLoop.h"

#include <array>
#include <stdexcept>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "TimeProvider.h"

namespace tailgate::uwp
{

EventLoop::EventLoop()
{
    const auto handle = CreateEventExW(nullptr, nullptr, 0, SYNCHRONIZE | EVENT_MODIFY_STATE);
    if (handle == nullptr)
    {
        winrt::throw_last_error();
    }
    m_wake.attach(handle);
}

base::EventWaitResult EventLoop::Wait(std::size_t)
{
    if (WaitForSingleObjectEx(m_wake.get(), INFINITE, FALSE) == WAIT_FAILED)
    {
        winrt::throw_last_error();
    }
    return base::EventWaitResult{.Status = base::EventWaitStatus::Woken, .Events = {}};
}

base::EventWaitResult EventLoop::Wait(const base::WaitToken& waitToken, std::size_t)
{
    const auto& deadline = dynamic_cast<const WaitToken&>(waitToken);
    const std::array<HANDLE, 2> handles{m_wake.get(), deadline.Handle()};
    const auto result =
        WaitForMultipleObjectsEx(handles.size(), handles.data(), FALSE, INFINITE, FALSE);
    if (result == WAIT_FAILED)
    {
        winrt::throw_last_error();
    }
    return base::EventWaitResult{
        .Status = result == WAIT_OBJECT_0 ? base::EventWaitStatus::Woken
                                          : base::EventWaitStatus::DeadlineReached,
        .Events = {},
    };
}

void EventLoop::Wake() noexcept
{
    if (!SetEvent(m_wake.get()))
    {
        m_logger.LogWarning("failed to wake the node worker");
    }
}

} // namespace tailgate::uwp
