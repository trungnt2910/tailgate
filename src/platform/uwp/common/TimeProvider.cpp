#include "TimeProvider.h"

#include <chrono>
#include <memory>

#include <winrt/Windows.Foundation.h>

namespace tailgate::uwp
{

WaitToken::WaitToken(base::TimeProvider::TimePoint deadline)
    : m_signal(std::make_shared<EventSignal>())
{
    const auto now = base::TimeProvider::NativeClock::now();
    if (deadline <= now)
    {
        m_signal->Set();
        return;
    }
    const auto delay = std::chrono::ceil<winrt::Windows::Foundation::TimeSpan>(deadline - now);
    // Cancellation can race an already dispatched callback. Capture the signal,
    // not the token, so that callback never accesses a destroyed owner.
    m_timer = winrt::Windows::System::Threading::ThreadPoolTimer::CreateTimer(
        [signal = m_signal](const auto&)
        {
            signal->Set();
        },
        delay);
}

WaitToken::~WaitToken()
{
    if (m_timer)
    {
        try
        {
            m_timer.Cancel();
        }
        catch (const winrt::hresult_error& error)
        {
            m_logger.LogWarning("failed to cancel deadline timer hresult={}", error.code().value);
        }
    }
}

void* WaitToken::Handle() const noexcept
{
    return m_signal->Handle();
}

base::TimeProvider::TimePoint TimeProvider::Now() const noexcept
{
    return NativeClock::now();
}

std::unique_ptr<base::WaitToken> TimeProvider::At(TimePoint timePoint)
{
    return std::make_unique<WaitToken>(timePoint);
}

} // namespace tailgate::uwp
