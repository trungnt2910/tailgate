#include <tailgate/base/Clock.h>

namespace tailgate::base
{

IClock::TimePoint SteadyClock::Now() const noexcept
{
    return Clock::now();
}

} // namespace tailgate::base
