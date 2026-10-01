#include "TimeProvider.h"

#include <chrono>
#include <memory>
#include <mutex>
#include <utility>

#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.System.Threading.h>

#include <tailgate/base/Logger.h>

#include "EventSignal.h"

namespace tailgate::uwp
{

class WaitToken::State final : public std::enable_shared_from_this<State>
{
public:
    explicit State(base::TimeProvider::TimePoint deadline) : m_deadline(deadline)
    {
    }

    void Arm()
    {
        std::lock_guard lock(m_mutex);
        if (m_cancelled)
        {
            return;
        }
        const auto now = base::TimeProvider::NativeClock::now();
        if (m_deadline <= now)
        {
            m_signal.Set();
            return;
        }
        // Windows timer completion is a wakeup, not proof that the steady-clock
        // deadline elapsed. Re-arm early callbacks, rounding up to a whole ms so
        // a fractional remainder never becomes an immediate timer loop.
        const auto delay = std::chrono::ceil<std::chrono::milliseconds>(m_deadline - now);
        m_timer = winrt::Windows::System::Threading::ThreadPoolTimer::CreateTimer(
            [weak = weak_from_this()](const auto&)
            {
                if (const auto state = weak.lock())
                {
                    state->Arm();
                }
            },
            delay);
    }

    void Cancel() noexcept
    {
        winrt::Windows::System::Threading::ThreadPoolTimer timer{nullptr};
        {
            std::lock_guard lock(m_mutex);
            m_cancelled = true;
            timer = std::exchange(m_timer, nullptr);
        }
        // An already dispatched callback can still hold State, but cannot re-arm
        // after cancellation. Cancel outside the lock used by that callback.
        if (timer)
        {
            try
            {
                timer.Cancel();
            }
            catch (const winrt::hresult_error& error)
            {
                m_logger.LogWarning("failed to cancel deadline timer hresult={}",
                                    error.code().value);
            }
        }
    }

    [[nodiscard]] void* Handle() const noexcept
    {
        return m_signal.Handle();
    }

private:
    const base::TimeProvider::TimePoint m_deadline;
    EventSignal m_signal;
    std::mutex m_mutex;
    bool m_cancelled = false;
    winrt::Windows::System::Threading::ThreadPoolTimer m_timer{nullptr};
    base::Logger m_logger{"uwp-wait-token"};
};

WaitToken::WaitToken(base::TimeProvider::TimePoint deadline)
    : m_state(std::make_shared<State>(deadline))
{
    m_state->Arm();
}

WaitToken::~WaitToken()
{
    m_state->Cancel();
}

void* WaitToken::Handle() const noexcept
{
    return m_state->Handle();
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
