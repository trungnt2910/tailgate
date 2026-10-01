#pragma once

#include <winrt/base.h>

#include <tailgate/base/EventLoop.h>
#include <tailgate/base/Logger.h>

namespace tailgate::uwp
{

// Completion notifications wake a dedicated node worker. VPN callbacks never wait here.
class EventLoop final : public base::EventLoop
{
public:
    EventLoop();
    [[nodiscard]] base::EventWaitResult Wait(std::size_t maximumEvents) override;
    [[nodiscard]] base::EventWaitResult Wait(const base::WaitToken& waitToken,
                                             std::size_t maximumEvents) override;
    void Wake() noexcept override;

private:
    winrt::handle m_wake;
    base::Logger m_logger{"uwp-event-loop"};
};

} // namespace tailgate::uwp
