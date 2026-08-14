#pragma once

#include <chrono>

namespace tailgate::control::client
{

class RetryBackoff final
{
public:
    RetryBackoff(std::chrono::milliseconds initialDelay, std::chrono::milliseconds maximumDelay);

    [[nodiscard]] std::chrono::milliseconds NextDelay();
    void Reset();

private:
    std::chrono::milliseconds m_initialDelay;
    std::chrono::milliseconds m_maximumDelay;
    std::chrono::milliseconds m_nextDelay;
};

} // namespace tailgate::control::client
