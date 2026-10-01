#include <chrono>
#include <future>

#include <gtest/gtest.h>

#include "common/EventLoop.h"
#include "common/TimeProvider.h"

TEST(Given_UwpEventLoop, When_CompletionIsPostedBeforeWait_Then_WakeAndReadinessAreRetained)
{
    tailgate::uwp::EventLoop loop;
    tailgate::uwp::TimeProvider time;
    auto deadline = time.After(std::chrono::seconds(2));
    const tailgate::base::EventToken token{.Value = 7};

    loop.Post({.Token = token, .Readiness = tailgate::base::EventReadiness::Readable});
    const auto wait = loop.Wait(*deadline, 1);
    const auto events = loop.TakePostedEvents(1);
    ASSERT_EQ(events.size(), 1U);

    EXPECT_EQ(wait.Status, tailgate::base::EventWaitStatus::Woken);
    EXPECT_EQ(events.front().Token, token);
    EXPECT_EQ(events.front().Readiness, tailgate::base::EventReadiness::Readable);
}

TEST(Given_UwpEventLoop, When_DeadlineHasPassed_Then_WaitReportsDeadline)
{
    tailgate::uwp::EventLoop loop;
    tailgate::uwp::TimeProvider time;
    auto deadline = time.At(time.Now());

    const auto result = loop.Wait(*deadline, 1);

    EXPECT_EQ(result.Status, tailgate::base::EventWaitStatus::DeadlineReached);
}

TEST(Given_UwpEventLoop, When_WorkerIsWaiting_Then_WakeReleasesIt)
{
    tailgate::uwp::EventLoop loop;
    tailgate::uwp::TimeProvider time;
    auto deadline = time.After(std::chrono::seconds(2));
    std::promise<void> started;
    auto result = std::async(std::launch::async,
                             [&]
                             {
                                 started.set_value();
                                 return loop.Wait(*deadline, 1);
                             });
    started.get_future().wait();

    loop.Wake();
    const auto observed = result.get();

    EXPECT_EQ(observed.Status, tailgate::base::EventWaitStatus::Woken);
}
