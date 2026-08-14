#include <tailgate/control/client/RetryBackoff.h>

#include <algorithm>
#include <stdexcept>

namespace tailgate::control::client
{

RetryBackoff::RetryBackoff(std::chrono::milliseconds initialDelay,
                           std::chrono::milliseconds maximumDelay)
    : m_initialDelay(initialDelay), m_maximumDelay(maximumDelay), m_nextDelay(initialDelay)
{
    if (initialDelay <= std::chrono::milliseconds::zero() || maximumDelay < initialDelay)
    {
        throw std::invalid_argument("Retry backoff delays are invalid.");
    }
}

std::chrono::milliseconds RetryBackoff::NextDelay()
{
    const std::chrono::milliseconds result = m_nextDelay;
    m_nextDelay = m_nextDelay > m_maximumDelay - m_nextDelay ? m_maximumDelay : m_nextDelay * 2;
    return result;
}

void RetryBackoff::Reset()
{
    m_nextDelay = m_initialDelay;
}

} // namespace tailgate::control::client
