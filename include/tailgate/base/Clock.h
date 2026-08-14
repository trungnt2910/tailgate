#pragma once

#include <chrono>

namespace tailgate::base
{

class IClock
{
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;

    virtual ~IClock() = default;
    [[nodiscard]] virtual TimePoint Now() const noexcept = 0;
};

class SteadyClock final : public IClock
{
public:
    [[nodiscard]] TimePoint Now() const noexcept override;
};

} // namespace tailgate::base
