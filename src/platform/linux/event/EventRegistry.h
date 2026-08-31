#pragma once

#include <cstdint>
#include <memory>
#include <optional>

#include <tailgate/base/EventLoop.h>

#include "UniqueFd.h"

namespace tailgate::linux_frontend::event
{

enum class EventInterest : std::uint8_t
{
    Readable = 1U << 0U,
    Writable = 1U << 1U,
};

[[nodiscard]] constexpr EventInterest operator|(EventInterest left, EventInterest right) noexcept
{
    return static_cast<EventInterest>(static_cast<std::uint8_t>(left) |
                                      static_cast<std::uint8_t>(right));
}

class EventRegistry;

class EventHandle final
{
public:
    EventHandle() = default;
    ~EventHandle();
    EventHandle(const EventHandle&) = delete;
    EventHandle& operator=(const EventHandle&) = delete;
    EventHandle(EventHandle&& other) noexcept;
    EventHandle& operator=(EventHandle&& other) noexcept;

    void Modify(EventInterest interest);
    void Reset() noexcept;

private:
    friend class EventRegistry;

    EventHandle(std::shared_ptr<EventRegistry> registry,
                int descriptor,
                tailgate::base::EventToken token);

    std::shared_ptr<EventRegistry> m_registry;
    int m_descriptor = -1;
    tailgate::base::EventToken m_token;
};

class EventRegistry final : public std::enable_shared_from_this<EventRegistry>
{
public:
    EventRegistry();

    [[nodiscard]] EventHandle
    Register(int descriptor, EventInterest interest, tailgate::base::EventToken token);
    [[nodiscard]] tailgate::base::EventWaitResult Wait(std::optional<int> timerDescriptor,
                                                       std::size_t maximumEvents);
    void Wake() noexcept;

private:
    friend class EventHandle;

    void Modify(int descriptor, EventInterest interest, tailgate::base::EventToken token);
    void Remove(int descriptor) noexcept;

    UniqueFd m_epoll;
    UniqueFd m_wake;
};

} // namespace tailgate::linux_frontend::event
