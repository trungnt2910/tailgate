#include <chrono>
#include <vector>

#include <gtest/gtest.h>

#include <tailgate/control/RetryBackoff.h>

TEST(Given_RetryBackoff, When_AdvancingPastMaximum_Then_DelayIsCapped)
{
    tailgate::control::RetryBackoff backoff(std::chrono::seconds(1), std::chrono::seconds(30));

    const std::vector<std::chrono::milliseconds> delays{
        backoff.NextDelay(),
        backoff.NextDelay(),
        backoff.NextDelay(),
        backoff.NextDelay(),
        backoff.NextDelay(),
        backoff.NextDelay(),
        backoff.NextDelay(),
    };

    EXPECT_EQ(delays,
              (std::vector<std::chrono::milliseconds>{std::chrono::seconds(1),
                                                      std::chrono::seconds(2),
                                                      std::chrono::seconds(4),
                                                      std::chrono::seconds(8),
                                                      std::chrono::seconds(16),
                                                      std::chrono::seconds(30),
                                                      std::chrono::seconds(30)}));
}

TEST(Given_AdvancedRetryBackoff, When_Resetting_Then_InitialDelayIsRestored)
{
    tailgate::control::RetryBackoff backoff(std::chrono::seconds(1), std::chrono::seconds(30));
    (void)backoff.NextDelay();
    (void)backoff.NextDelay();

    backoff.Reset();
    const std::chrono::milliseconds delay = backoff.NextDelay();

    EXPECT_EQ(delay, std::chrono::seconds(1));
}

TEST(Given_InvalidRetryBackoffRange, When_Constructing_Then_ItIsRejected)
{
    const auto construct = []
    {
        tailgate::control::RetryBackoff backoff(std::chrono::seconds(2), std::chrono::seconds(1));
    };

    EXPECT_THROW(construct(), std::invalid_argument);
}
