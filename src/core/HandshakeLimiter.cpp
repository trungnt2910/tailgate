#include "tailgate/serve/HandshakeLimiter.h"

#include <algorithm>
#include <stdexcept>

namespace tailgate::serve
{

HandshakeLimiter::HandshakeLimiter(std::size_t maximumPending,
                                   std::size_t burst,
                                   Clock::duration refillInterval,
                                   Clock::time_point now)
    : m_maximumPending(maximumPending),
      m_burst(burst),
      m_refillInterval(refillInterval),
      m_lastRefill(now),
      m_tokens(burst)
{
    if (maximumPending == 0 || burst == 0 || refillInterval <= Clock::duration::zero())
    {
        throw std::invalid_argument("Handshake limiter values must be positive.");
    }
}

bool HandshakeLimiter::TryBegin(Clock::time_point now)
{
    Refill(now);
    if (m_pending >= m_maximumPending || m_tokens == 0)
    {
        return false;
    }
    --m_tokens;
    ++m_pending;
    return true;
}

void HandshakeLimiter::Finish()
{
    if (m_pending == 0)
    {
        throw std::logic_error("Handshake limiter has no pending operation.");
    }
    --m_pending;
}

std::size_t HandshakeLimiter::Pending() const
{
    return m_pending;
}

void HandshakeLimiter::Refill(Clock::time_point now)
{
    if (now <= m_lastRefill)
    {
        return;
    }
    const auto elapsed = now - m_lastRefill;
    const auto intervals = elapsed / m_refillInterval;
    if (intervals <= 0)
    {
        return;
    }
    const auto added = static_cast<std::size_t>(intervals);
    m_tokens = std::min(m_burst, m_tokens + added);
    m_lastRefill += m_refillInterval * intervals;
}

} // namespace tailgate::serve
