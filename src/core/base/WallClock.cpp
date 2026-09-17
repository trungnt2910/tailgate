#include "tailgate/base/WallClock.h"

namespace tailgate::base
{

WallClock::~WallClock() = default;

WallClock::TimePoint WallClock::Now() const noexcept
{
    return std::chrono::system_clock::now();
}

} // namespace tailgate::base
