#include "TimeProvider.h"

#include <cerrno>
#include <chrono>
#include <memory>
#include <system_error>
#include <utility>

#include <sys/timerfd.h>
#include <time.h>

namespace tailgate::linux_frontend::impl
{
namespace
{

timespec ToTimespec(tailgate::base::TimeProvider::TimePoint timePoint) noexcept
{
    using namespace std::chrono;
    nanoseconds elapsed = duration_cast<nanoseconds>(timePoint.time_since_epoch());
    if (elapsed <= nanoseconds::zero())
    {
        elapsed = nanoseconds(1);
    }
    const seconds wholeSeconds = duration_cast<seconds>(elapsed);
    const nanoseconds remainder = elapsed - wholeSeconds;
    return timespec{
        .tv_sec = static_cast<time_t>(wholeSeconds.count()),
        .tv_nsec = static_cast<long>(remainder.count()),
    };
}

} // namespace

WaitToken::WaitToken(UniqueFd descriptor) noexcept : m_descriptor(std::move(descriptor))
{
}

int WaitToken::Descriptor() const noexcept
{
    return m_descriptor.Fd;
}

tailgate::base::TimeProvider::TimePoint TimeProvider::Now() const noexcept
{
    timespec current{};
    if (clock_gettime(CLOCK_MONOTONIC, &current) != 0)
    {
        return {};
    }
    const auto elapsed =
        std::chrono::seconds(current.tv_sec) + std::chrono::nanoseconds(current.tv_nsec);
    return TimePoint(std::chrono::duration_cast<Duration>(elapsed));
}

std::unique_ptr<tailgate::base::WaitToken> TimeProvider::At(TimePoint timePoint)
{
    UniqueFd descriptor(timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK));
    if (descriptor.Fd < 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    itimerspec timer{};
    timer.it_value = ToTimespec(timePoint);
    if (timerfd_settime(descriptor.Fd, TFD_TIMER_ABSTIME, &timer, nullptr) != 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    return std::make_unique<WaitToken>(std::move(descriptor));
}

} // namespace tailgate::linux_frontend::impl
