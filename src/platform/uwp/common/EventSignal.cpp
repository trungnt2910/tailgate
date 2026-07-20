#include "common/EventSignal.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace tailgate::uwp
{

EventSignal::EventSignal()
{
    const HANDLE signal = CreateEventExW(
        nullptr, nullptr, CREATE_EVENT_MANUAL_RESET, SYNCHRONIZE | EVENT_MODIFY_STATE);
    if (signal == nullptr)
    {
        winrt::throw_last_error();
    }
    m_signal.attach(signal);
}

void* EventSignal::Handle() const noexcept
{
    return m_signal.get();
}

void EventSignal::Set() const noexcept
{
    if (!SetEvent(m_signal.get()))
    {
        m_logger.LogWarning("failed to signal a Windows event");
    }
}

} // namespace tailgate::uwp
