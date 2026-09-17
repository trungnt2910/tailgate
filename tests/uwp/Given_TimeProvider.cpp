#include <chrono>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <gtest/gtest.h>

#include "common/TimeProvider.h"

TEST(Given_TimeProvider, When_ReadingTime_Then_UsesTheSteadyClock)
{
    tailgate::uwp::TimeProvider provider;
    const auto before = tailgate::base::TimeProvider::NativeClock::now();

    const auto now = provider.Now();
    const auto after = tailgate::base::TimeProvider::NativeClock::now();

    EXPECT_GE(now, before);
    EXPECT_LE(now, after);
}

TEST(Given_TimeProvider, When_DeadlineIsPast_Then_WaitTokenIsAlreadySignaled)
{
    tailgate::uwp::TimeProvider provider;

    const auto token = provider.At(tailgate::base::TimeProvider::TimePoint::min());
    const auto* native = dynamic_cast<const tailgate::uwp::WaitToken*>(token.get());
    const auto result =
        native != nullptr ? WaitForSingleObjectEx(native->Handle(), 0, FALSE) : WAIT_FAILED;

    EXPECT_NE(native, nullptr);
    EXPECT_EQ(result, WAIT_OBJECT_0);
}

TEST(Given_TimeProvider, When_WaitingForFutureDeadline_Then_TimerSignalsAtTheDeadline)
{
    tailgate::uwp::TimeProvider provider;
    const auto deadline = provider.Now() + std::chrono::milliseconds(20);
    constexpr DWORD TestWaitLimitMilliseconds = 2000;

    const auto token = provider.At(deadline);
    const auto* native = dynamic_cast<const tailgate::uwp::WaitToken*>(token.get());
    const auto result =
        native != nullptr
            ? WaitForSingleObjectEx(native->Handle(), TestWaitLimitMilliseconds, FALSE)
            : WAIT_FAILED;
    const auto completed = provider.Now();

    EXPECT_NE(native, nullptr);
    EXPECT_EQ(result, WAIT_OBJECT_0);
    EXPECT_GE(completed, deadline);
}
