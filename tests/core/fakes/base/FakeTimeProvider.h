#pragma once

#include <algorithm>
#include <condition_variable>
#include <cstddef>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include <tailgate/base/TimeProvider.h>

namespace tailgate::tests::fakes
{
namespace detail
{

struct FakeWaitState
{
    std::condition_variable Changed;
    std::mutex Mutex;
    bool Signaled = false;
};

} // namespace detail

class FakeWaitToken final : public tailgate::base::WaitToken
{
public:
    explicit FakeWaitToken(std::shared_ptr<detail::FakeWaitState> state) noexcept
        : m_state(std::move(state))
    {
    }

    void Wait() const
    {
        std::unique_lock lock(m_state->Mutex);
        m_state->Changed.wait(lock,
                              [&]()
                              {
                                  return m_state->Signaled;
                              });
    }

    [[nodiscard]] bool IsSignaled() const noexcept
    {
        std::lock_guard lock(m_state->Mutex);
        return m_state->Signaled;
    }

private:
    std::shared_ptr<detail::FakeWaitState> m_state;
};

class FakeTimeProvider final : public tailgate::base::TimeProvider
{
public:
    explicit FakeTimeProvider(TimePoint now = {}) noexcept : m_now(now)
    {
    }

    [[nodiscard]] TimePoint Now() const noexcept override
    {
        std::lock_guard lock(m_mutex);
        return m_now;
    }

    [[nodiscard]] std::unique_ptr<tailgate::base::WaitToken> At(TimePoint timePoint) override
    {
        auto state = std::make_shared<detail::FakeWaitState>();
        bool due = false;
        {
            std::lock_guard lock(m_mutex);
            due = timePoint <= m_now;
            if (!due)
            {
                m_pending.push_back(PendingWait{.Deadline = timePoint, .State = state});
            }
        }
        if (due)
        {
            Signal(*state);
        }
        return std::make_unique<FakeWaitToken>(std::move(state));
    }

    void Set(TimePoint now)
    {
        std::vector<std::shared_ptr<detail::FakeWaitState>> due;
        {
            std::lock_guard lock(m_mutex);
            m_now = now;
            auto pending = std::remove_if(m_pending.begin(),
                                          m_pending.end(),
                                          [&](const PendingWait& wait)
                                          {
                                              std::shared_ptr<detail::FakeWaitState> state =
                                                  wait.State.lock();
                                              if (state == nullptr)
                                              {
                                                  return true;
                                              }
                                              if (wait.Deadline <= m_now)
                                              {
                                                  due.push_back(std::move(state));
                                                  return true;
                                              }
                                              return false;
                                          });
            m_pending.erase(pending, m_pending.end());
        }
        for (const auto& state : due)
        {
            Signal(*state);
        }
    }

    void Advance(Duration duration)
    {
        Set(Now() + duration);
    }

    [[nodiscard]] std::size_t PendingWaitCount() const noexcept
    {
        std::lock_guard lock(m_mutex);
        return static_cast<std::size_t>(std::count_if(m_pending.begin(),
                                                      m_pending.end(),
                                                      [](const PendingWait& wait)
                                                      {
                                                          return !wait.State.expired();
                                                      }));
    }

private:
    struct PendingWait
    {
        TimePoint Deadline;
        std::weak_ptr<detail::FakeWaitState> State;
    };

    static void Signal(detail::FakeWaitState& state) noexcept
    {
        {
            std::lock_guard lock(state.Mutex);
            state.Signaled = true;
        }
        state.Changed.notify_all();
    }

    mutable std::mutex m_mutex;
    TimePoint m_now;
    std::vector<PendingWait> m_pending;
};

} // namespace tailgate::tests::fakes
