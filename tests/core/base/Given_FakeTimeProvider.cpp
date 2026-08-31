#include <chrono>
#include <memory>

#include <gtest/gtest.h>

#include <tailgate/base/TimeProvider.h>

#include "fakes/base/FakeTimeProvider.h"

TEST(Given_FakeTimeProvider, When_TimeReachesDeadline_Then_WaitTokenIsSignaled)
{
    tailgate::tests::fakes::FakeTimeProvider timeProvider;
    constexpr auto Duration = std::chrono::seconds(5);
    std::unique_ptr<tailgate::base::WaitToken> waitToken = timeProvider.After(Duration);
    auto& fakeWaitToken = dynamic_cast<tailgate::tests::fakes::FakeWaitToken&>(*waitToken);
    const bool signaledBeforeDeadline = fakeWaitToken.IsSignaled();

    timeProvider.Advance(Duration);

    EXPECT_FALSE(signaledBeforeDeadline);
    EXPECT_TRUE(fakeWaitToken.IsSignaled());
    EXPECT_EQ(timeProvider.Now(), tailgate::base::TimeProvider::TimePoint(Duration));
}

TEST(Given_FakeTimeProvider, When_WaitTokenIsDestroyed_Then_DeadlineIsCancelled)
{
    tailgate::tests::fakes::FakeTimeProvider timeProvider;
    constexpr auto Duration = std::chrono::seconds(5);
    std::unique_ptr<tailgate::base::WaitToken> waitToken = timeProvider.After(Duration);

    waitToken.reset();
    timeProvider.Advance(Duration);

    EXPECT_EQ(timeProvider.PendingWaitCount(), 0U);
}
