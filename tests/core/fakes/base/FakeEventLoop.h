#pragma once

#include <condition_variable>
#include <cstddef>
#include <mutex>
#include <utility>

#include <tailgate/base/EventLoop.h>

#include "fakes/base/FakeTimeProvider.h"

namespace tailgate::tests::fakes
{

class FakeEventLoop final : public tailgate::base::EventLoop
{
public:
    tailgate::base::EventWaitResult Wait(std::size_t) override
    {
        ++WaitCalls;
        return std::move(Next);
    }

    tailgate::base::EventWaitResult Wait(const tailgate::base::WaitToken& waitToken,
                                         std::size_t) override
    {
        ++TimedWaitCalls;
        if (!Next.Events.empty() || Next.Status != tailgate::base::EventWaitStatus::Events)
        {
            return std::move(Next);
        }
        dynamic_cast<const FakeWaitToken&>(waitToken).Wait();
        return tailgate::base::EventWaitResult{
            .Status = tailgate::base::EventWaitStatus::DeadlineReached,
            .Events = {},
        };
    }

    void Wake() noexcept override
    {
        {
            const std::scoped_lock lock(m_mutex);
            ++m_wakeCalls;
        }
        m_wakeCondition.notify_all();
    }

    void WaitForWake()
    {
        std::unique_lock lock(m_mutex);
        m_wakeCondition.wait(lock,
                             [this]()
                             {
                                 return m_wakeCalls != 0;
                             });
    }

    [[nodiscard]] std::size_t WakeCalls() const
    {
        const std::scoped_lock lock(m_mutex);
        return m_wakeCalls;
    }

    tailgate::base::EventWaitResult Next;
    std::size_t WaitCalls = 0;
    std::size_t TimedWaitCalls = 0;

private:
    mutable std::mutex m_mutex;
    std::condition_variable m_wakeCondition;
    std::size_t m_wakeCalls = 0;
};

} // namespace tailgate::tests::fakes
