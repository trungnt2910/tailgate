#include "EventLoop.h"

#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>

#include <tailgate/base/EventLoop.h>

#include "TimeProvider.h"

namespace tailgate::linux_frontend::impl
{
namespace
{

constexpr const char* ForeignWaitTokenError = "wait token was created by another time provider";

} // namespace

EventLoop::EventLoop(std::shared_ptr<tailgate::linux_frontend::event::EventRegistry> registry)
    : m_registry(std::move(registry))
{
}

tailgate::base::EventWaitResult EventLoop::Wait(std::size_t maximumEvents)
{
    return m_registry->Wait(std::nullopt, maximumEvents);
}

tailgate::base::EventWaitResult EventLoop::Wait(const tailgate::base::WaitToken& waitToken,
                                                std::size_t maximumEvents)
{
    const auto* linuxToken = dynamic_cast<const WaitToken*>(&waitToken);
    if (linuxToken == nullptr)
    {
        throw std::invalid_argument(ForeignWaitTokenError);
    }
    return m_registry->Wait(linuxToken->Descriptor(), maximumEvents);
}

void EventLoop::Wake() noexcept
{
    m_registry->Wake();
}

} // namespace tailgate::linux_frontend::impl
