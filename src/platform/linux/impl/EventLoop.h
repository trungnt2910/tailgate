#pragma once

#include <memory>

#include <tailgate/base/EventLoop.h>

#include "event/EventRegistry.h"

namespace tailgate::linux_frontend::impl
{

class EventLoop final : public tailgate::base::EventLoop
{
public:
    explicit EventLoop(std::shared_ptr<tailgate::linux_frontend::event::EventRegistry> registry);

    [[nodiscard]] tailgate::base::EventWaitResult Wait(std::size_t maximumEvents) override;
    [[nodiscard]] tailgate::base::EventWaitResult Wait(const tailgate::base::WaitToken& waitToken,
                                                       std::size_t maximumEvents) override;
    void Wake() noexcept override;

private:
    std::shared_ptr<tailgate::linux_frontend::event::EventRegistry> m_registry;
};

} // namespace tailgate::linux_frontend::impl
