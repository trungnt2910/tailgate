#pragma once

#include <chrono>
#include <memory>

namespace tailgate::base
{

class WaitToken
{
public:
    virtual ~WaitToken();

protected:
    WaitToken() = default;
};

class TimeProvider
{
public:
    using NativeClock = std::chrono::steady_clock;
    using Duration = NativeClock::duration;
    using TimePoint = NativeClock::time_point;

    virtual ~TimeProvider();
    [[nodiscard]] virtual TimePoint Now() const noexcept = 0;
    [[nodiscard]] virtual std::unique_ptr<WaitToken> At(TimePoint timePoint) = 0;

    [[nodiscard]] std::unique_ptr<WaitToken> After(Duration duration)
    {
        return At(Now() + duration);
    }
};

} // namespace tailgate::base
