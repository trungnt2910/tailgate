#include <gtest/gtest.h>

#include "fakes/base/FakeEventLoop.h"

TEST(Given_EventLoop, When_CompletionsShareToken_Then_ReadinessIsCoalesced)
{
    tailgate::tests::fakes::FakeEventLoop events;
    const tailgate::base::EventToken token{.Value = 1};

    events.Post({.Token = token, .Readiness = tailgate::base::EventReadiness::Readable});
    events.Post({.Token = token, .Readiness = tailgate::base::EventReadiness::Writable});
    const auto ready = events.TakePostedEvents(1);
    const auto remaining = events.TakePostedEvents(1);
    ASSERT_EQ(ready.size(), 1U);

    EXPECT_EQ(ready.front().Token, token);
    EXPECT_TRUE(tailgate::base::HasReadiness(ready.front().Readiness,
                                             tailgate::base::EventReadiness::Readable));
    EXPECT_TRUE(tailgate::base::HasReadiness(ready.front().Readiness,
                                             tailgate::base::EventReadiness::Writable));
    EXPECT_TRUE(remaining.empty());
}

TEST(Given_EventLoop, When_BatchIsLimited_Then_RemainingCompletionsWakeNextWait)
{
    tailgate::tests::fakes::FakeEventLoop events;
    events.Post({.Token = {.Value = 1}, .Readiness = tailgate::base::EventReadiness::Readable});
    events.Post({.Token = {.Value = 2}, .Readiness = tailgate::base::EventReadiness::Writable});
    const auto before = events.WakeCalls();

    const auto first = events.TakePostedEvents(1);
    const auto after = events.WakeCalls();
    const auto second = events.TakePostedEvents(1);
    ASSERT_EQ(first.size(), 1U);
    ASSERT_EQ(second.size(), 1U);

    EXPECT_NE(first.front().Token, second.front().Token);
    EXPECT_EQ(after, before + 1);
}

TEST(Given_EventLoop, When_ProducerRetires_Then_OnlyItsQueuedReadinessIsDiscarded)
{
    tailgate::tests::fakes::FakeEventLoop events;
    const tailgate::base::EventToken retired{.Value = 1};
    const tailgate::base::EventToken active{.Value = 2};
    events.Post({.Token = retired, .Readiness = tailgate::base::EventReadiness::Error});
    events.Post({.Token = active, .Readiness = tailgate::base::EventReadiness::Readable});

    events.DiscardPostedEvents(retired);
    const auto ready = events.TakePostedEvents(8);
    ASSERT_EQ(ready.size(), 1U);

    EXPECT_EQ(ready.front().Token, active);
    EXPECT_EQ(ready.front().Readiness, tailgate::base::EventReadiness::Readable);
}
