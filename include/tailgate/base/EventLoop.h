#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include <tailgate/base/TimeProvider.h>

namespace tailgate::base
{

struct EventToken
{
    std::uint64_t Value = 0;

    [[nodiscard]] bool operator==(const EventToken&) const noexcept = default;
};

enum class EventReadiness : std::uint8_t
{
    None = 0,
    Readable = 1U << 0U,
    Writable = 1U << 1U,
    Closed = 1U << 2U,
    Error = 1U << 3U,
};

[[nodiscard]] constexpr EventReadiness operator|(EventReadiness left, EventReadiness right) noexcept
{
    return static_cast<EventReadiness>(static_cast<std::uint8_t>(left) |
                                       static_cast<std::uint8_t>(right));
}

[[nodiscard]] constexpr bool HasReadiness(EventReadiness value, EventReadiness readiness) noexcept
{
    return (static_cast<std::uint8_t>(value) & static_cast<std::uint8_t>(readiness)) != 0;
}

struct Event
{
    EventToken Token;
    EventReadiness Readiness = EventReadiness::None;
};

enum class EventWaitStatus
{
    Events,
    DeadlineReached,
    Woken,
};

struct EventWaitResult
{
    EventWaitStatus Status = EventWaitStatus::Events;
    std::vector<Event> Events;
};

class EventLoop
{
public:
    virtual ~EventLoop();

    [[nodiscard]] virtual EventWaitResult Wait(std::size_t maximumEvents) = 0;
    [[nodiscard]] virtual EventWaitResult Wait(const WaitToken& waitToken,
                                               std::size_t maximumEvents) = 0;
    virtual void Wake() noexcept = 0;
};

} // namespace tailgate::base
