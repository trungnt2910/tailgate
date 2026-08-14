#include <gtest/gtest.h>

#include <tailgate/serve/HandshakeLimiter.h>

using namespace std::chrono_literals;

TEST(Given_HandshakeBurstIsExhausted, When_TimeDoesNotAdvance_Then_NewWorkIsRejected)
{
    const tailgate::serve::HandshakeLimiter::Clock::time_point start{};
    tailgate::serve::HandshakeLimiter limiter(4, 2, 1s, start);

    const bool first = limiter.TryBegin(start);
    const bool second = limiter.TryBegin(start);
    const bool third = limiter.TryBegin(start);

    EXPECT_TRUE(first);
    EXPECT_TRUE(second);
    EXPECT_FALSE(third);
    EXPECT_EQ(limiter.Pending(), 2U);
}

TEST(Given_HandshakeTokenRefills, When_CapacityIsAvailable_Then_NewWorkIsAccepted)
{
    const tailgate::serve::HandshakeLimiter::Clock::time_point start{};
    tailgate::serve::HandshakeLimiter limiter(2, 1, 1s, start);
    ASSERT_TRUE(limiter.TryBegin(start));
    limiter.Finish();

    const bool beforeRefill = limiter.TryBegin(start + 999ms);
    const bool afterRefill = limiter.TryBegin(start + 1s);

    EXPECT_FALSE(beforeRefill);
    EXPECT_TRUE(afterRefill);
    EXPECT_EQ(limiter.Pending(), 1U);
}

TEST(Given_PendingHandshakeLimitIsReached, When_TokensRemain_Then_NewWorkIsRejected)
{
    const tailgate::serve::HandshakeLimiter::Clock::time_point start{};
    tailgate::serve::HandshakeLimiter limiter(1, 2, 1s, start);
    ASSERT_TRUE(limiter.TryBegin(start));

    const bool accepted = limiter.TryBegin(start);

    EXPECT_FALSE(accepted);
    EXPECT_EQ(limiter.Pending(), 1U);
}
