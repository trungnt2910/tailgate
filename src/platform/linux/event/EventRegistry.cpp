#include "EventRegistry.h"

#include <cerrno>
#include <limits>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

namespace tailgate::linux_frontend::event
{
namespace
{

constexpr tailgate::base::EventToken WakeToken{};
constexpr std::uint64_t TimerToken = std::numeric_limits<std::uint64_t>::max();
constexpr const char* ReservedTokenError = "event token is reserved";
constexpr const char* UnregisteredHandleError = "event handle is not registered";
constexpr const char* InvalidEventCapacityError = "event capacity is outside the supported range";

std::uint32_t NativeEvents(EventInterest interest)
{
    const auto value = static_cast<std::uint8_t>(interest);
    std::uint32_t result = 0;
    if ((value & static_cast<std::uint8_t>(EventInterest::Readable)) != 0)
    {
        result |= EPOLLIN;
    }
    if ((value & static_cast<std::uint8_t>(EventInterest::Writable)) != 0)
    {
        result |= EPOLLOUT;
    }
    return result;
}

tailgate::base::EventReadiness Readiness(std::uint32_t events)
{
    tailgate::base::EventReadiness result = tailgate::base::EventReadiness::None;
    if ((events & EPOLLIN) != 0)
    {
        result = result | tailgate::base::EventReadiness::Readable;
    }
    if ((events & EPOLLOUT) != 0)
    {
        result = result | tailgate::base::EventReadiness::Writable;
    }
    if ((events & EPOLLHUP) != 0)
    {
        result = result | tailgate::base::EventReadiness::Closed;
    }
    if ((events & EPOLLERR) != 0)
    {
        result = result | tailgate::base::EventReadiness::Error;
    }
    return result;
}

void Configure(int epoll,
               int operation,
               int descriptor,
               EventInterest interest,
               tailgate::base::EventToken token)
{
    if (token == WakeToken || token.Value == TimerToken)
    {
        throw std::invalid_argument(ReservedTokenError);
    }
    epoll_event event{};
    event.events = NativeEvents(interest);
    event.data.u64 = token.Value;
    if (epoll_ctl(epoll, operation, descriptor, &event) != 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
}

} // namespace

EventHandle::EventHandle(std::shared_ptr<EventRegistry> registry,
                         int descriptor,
                         tailgate::base::EventToken token)
    : m_registry(std::move(registry)), m_descriptor(descriptor), m_token(token)
{
}

EventHandle::~EventHandle()
{
    Reset();
}

EventHandle::EventHandle(EventHandle&& other) noexcept
    : m_registry(std::move(other.m_registry)),
      m_descriptor(std::exchange(other.m_descriptor, -1)),
      m_token(other.m_token)
{
}

EventHandle& EventHandle::operator=(EventHandle&& other) noexcept
{
    if (this != &other)
    {
        Reset();
        m_registry = std::move(other.m_registry);
        m_descriptor = std::exchange(other.m_descriptor, -1);
        m_token = other.m_token;
    }
    return *this;
}

void EventHandle::Modify(EventInterest interest)
{
    if (!m_registry || m_descriptor < 0)
    {
        throw std::logic_error(UnregisteredHandleError);
    }
    m_registry->Modify(m_descriptor, interest, m_token);
}

void EventHandle::Reset() noexcept
{
    if (m_registry && m_descriptor >= 0)
    {
        m_registry->Remove(m_descriptor);
    }
    m_descriptor = -1;
    m_registry.reset();
}

EventRegistry::EventRegistry()
    : m_epoll(epoll_create1(EPOLL_CLOEXEC)), m_wake(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK))
{
    if (m_epoll.Fd < 0 || m_wake.Fd < 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
    epoll_event event{};
    event.events = EPOLLIN;
    event.data.u64 = WakeToken.Value;
    if (epoll_ctl(m_epoll.Fd, EPOLL_CTL_ADD, m_wake.Fd, &event) != 0)
    {
        throw std::system_error(errno, std::generic_category());
    }
}

EventHandle
EventRegistry::Register(int descriptor, EventInterest interest, tailgate::base::EventToken token)
{
    Configure(m_epoll.Fd, EPOLL_CTL_ADD, descriptor, interest, token);
    return EventHandle(shared_from_this(), descriptor, token);
}

void EventRegistry::Modify(int descriptor, EventInterest interest, tailgate::base::EventToken token)
{
    Configure(m_epoll.Fd, EPOLL_CTL_MOD, descriptor, interest, token);
}

void EventRegistry::Remove(int descriptor) noexcept
{
    (void)epoll_ctl(m_epoll.Fd, EPOLL_CTL_DEL, descriptor, nullptr);
}

tailgate::base::EventWaitResult EventRegistry::Wait(std::optional<int> timerDescriptor,
                                                    std::size_t maximumEvents)
{
    if (maximumEvents == 0 ||
        maximumEvents > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        throw std::invalid_argument(InvalidEventCapacityError);
    }
    if (timerDescriptor)
    {
        epoll_event timerEvent{};
        timerEvent.events = EPOLLIN;
        timerEvent.data.u64 = TimerToken;
        if (epoll_ctl(m_epoll.Fd, EPOLL_CTL_ADD, *timerDescriptor, &timerEvent) != 0)
        {
            throw std::system_error(errno, std::generic_category());
        }
    }

    class TimerRegistration
    {
    public:
        TimerRegistration(int epoll, std::optional<int> descriptor)
            : m_epoll(epoll), m_descriptor(descriptor)
        {
        }

        ~TimerRegistration()
        {
            if (m_descriptor)
            {
                (void)epoll_ctl(m_epoll, EPOLL_CTL_DEL, *m_descriptor, nullptr);
            }
        }

    private:
        int m_epoll;
        std::optional<int> m_descriptor;
    } registration(m_epoll.Fd, timerDescriptor);

    std::vector<epoll_event> nativeEvents(maximumEvents);
    const int count =
        epoll_wait(m_epoll.Fd, nativeEvents.data(), static_cast<int>(nativeEvents.size()), -1);
    if (count < 0)
    {
        if (errno == EINTR)
        {
            return tailgate::base::EventWaitResult{
                .Status = tailgate::base::EventWaitStatus::Woken,
                .Events = {},
            };
        }
        throw std::system_error(errno, std::generic_category());
    }
    tailgate::base::EventWaitResult result;
    result.Events.reserve(static_cast<std::size_t>(count));
    bool woken = false;
    bool deadlineReached = false;
    for (int index = 0; index < count; ++index)
    {
        const epoll_event& native = nativeEvents[static_cast<std::size_t>(index)];
        if (native.data.u64 == TimerToken)
        {
            std::uint64_t expirations = 0;
            (void)read(*timerDescriptor, &expirations, sizeof(expirations));
            deadlineReached = true;
            continue;
        }
        if (native.data.u64 == WakeToken.Value)
        {
            std::uint64_t value = 0;
            while (read(m_wake.Fd, &value, sizeof(value)) == sizeof(value))
            {
            }
            woken = true;
            continue;
        }
        result.Events.push_back(tailgate::base::Event{
            .Token = tailgate::base::EventToken{.Value = native.data.u64},
            .Readiness = Readiness(native.events),
        });
    }
    result.Status = deadlineReached ? tailgate::base::EventWaitStatus::DeadlineReached
                    : result.Events.empty() && woken ? tailgate::base::EventWaitStatus::Woken
                                                     : tailgate::base::EventWaitStatus::Events;
    return result;
}

void EventRegistry::Wake() noexcept
{
    constexpr std::uint64_t Increment = 1;
    (void)write(m_wake.Fd, &Increment, sizeof(Increment));
}

} // namespace tailgate::linux_frontend::event
