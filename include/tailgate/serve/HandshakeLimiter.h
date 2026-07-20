#pragma once

#include <chrono>
#include <cstddef>

namespace tailgate::serve
{

class HandshakeLimiter
{
public:
    using Clock = std::chrono::steady_clock;

    HandshakeLimiter(std::size_t maximumPending,
                     std::size_t burst,
                     Clock::duration refillInterval,
                     Clock::time_point now = Clock::now());

    [[nodiscard]] bool TryBegin(Clock::time_point now = Clock::now());
    void Finish();
    [[nodiscard]] std::size_t Pending() const;

private:
    void Refill(Clock::time_point now);

    std::size_t m_maximumPending;
    std::size_t m_burst;
    Clock::duration m_refillInterval;
    Clock::time_point m_lastRefill;
    std::size_t m_tokens;
    std::size_t m_pending = 0;
};

} // namespace tailgate::serve
