#include "LinuxDataplaneEvents.h"

#include <cerrno>
#include <cstring>
#include <stdexcept>

#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>

namespace tailgate::linux_frontend
{
namespace
{

constexpr std::uint64_t DataplaneEventKindShift = 32;

} // namespace

std::uint64_t PackDataplaneEvent(DataplaneEventKind kind, std::uint32_t index)
{
    return (static_cast<std::uint64_t>(kind) << DataplaneEventKindShift) | index;
}

DataplaneEvent UnpackDataplaneEvent(std::uint64_t value)
{
    return DataplaneEvent{.Kind = static_cast<DataplaneEventKind>(value >> DataplaneEventKindShift),
                          .Index = static_cast<std::uint32_t>(value)};
}

void AddEpollInterest(int epollFd, int fd, std::uint32_t events, std::uint64_t token)
{
    epoll_event event{};
    event.events = events;
    event.data.u64 = token;
    if (epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &event) != 0)
    {
        throw std::runtime_error("epoll add failed: " + std::string(std::strerror(errno)));
    }
}

void ModifyEpollInterest(int epollFd, int fd, std::uint32_t events, std::uint64_t token)
{
    epoll_event event{};
    event.events = events;
    event.data.u64 = token;
    if (epoll_ctl(epollFd, EPOLL_CTL_MOD, fd, &event) != 0)
    {
        throw std::runtime_error("epoll modify failed: " + std::string(std::strerror(errno)));
    }
}

UniqueFd CreateTimerFd(std::chrono::nanoseconds interval)
{
    UniqueFd timer(timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC));
    if (timer.Fd < 0)
    {
        throw std::runtime_error("timerfd_create failed: " + std::string(std::strerror(errno)));
    }

    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(interval);
    const auto nanoseconds =
        std::chrono::duration_cast<std::chrono::nanoseconds>(interval - seconds);
    itimerspec spec{};
    spec.it_interval.tv_sec = seconds.count();
    spec.it_interval.tv_nsec = nanoseconds.count();
    spec.it_value = spec.it_interval;
    if (timerfd_settime(timer.Fd, 0, &spec, nullptr) != 0)
    {
        throw std::runtime_error("timerfd_settime failed: " + std::string(std::strerror(errno)));
    }
    return timer;
}

UniqueFd CreateDeadlineTimerFd(std::chrono::nanoseconds timeout)
{
    UniqueFd timer(timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC));
    if (timer.Fd < 0)
    {
        throw std::runtime_error("timerfd_create failed: " + std::string(std::strerror(errno)));
    }
    ResetDeadlineTimerFd(timer.Fd, timeout);
    return timer;
}

void ResetDeadlineTimerFd(int fd, std::chrono::nanoseconds timeout)
{
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(timeout);
    const auto nanoseconds =
        std::chrono::duration_cast<std::chrono::nanoseconds>(timeout - seconds);
    itimerspec spec{};
    spec.it_value.tv_sec = seconds.count();
    spec.it_value.tv_nsec = nanoseconds.count();
    if (timerfd_settime(fd, 0, &spec, nullptr) != 0)
    {
        throw std::runtime_error("timerfd_settime failed: " + std::string(std::strerror(errno)));
    }
}

void DrainTimerFd(int fd)
{
    std::uint64_t expirations = 0;
    while (read(fd, &expirations, sizeof(expirations)) == sizeof(expirations))
    {
    }
    if (errno != EAGAIN && errno != EWOULDBLOCK)
    {
        throw std::runtime_error("timerfd drain failed: " + std::string(std::strerror(errno)));
    }
}

} // namespace tailgate::linux_frontend
