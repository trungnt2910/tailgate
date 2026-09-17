#pragma once

#include <chrono>

namespace tailgate::base
{

// Calendar time for protocol metadata, separate from monotonic scheduling deadlines.
class WallClock
{
public:
    using TimePoint = std::chrono::system_clock::time_point;

    virtual ~WallClock();
    [[nodiscard]] virtual TimePoint Now() const noexcept;
};

} // namespace tailgate::base
