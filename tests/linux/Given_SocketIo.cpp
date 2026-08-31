#include <cstddef>
#include <optional>

#include <gtest/gtest.h>

#include "impl/SocketIo.h"

TEST(Given_SocketIo, When_BlockingOperationNeedsReadiness_Then_ItWaitsBeforeRetrying)
{
    std::size_t attempts = 0;
    std::size_t waits = 0;

    const std::optional<std::size_t> result =
        tailgate::linux_frontend::impl::detail::CompleteSocketIo<std::size_t>(
            false,
            [&]() -> std::optional<std::size_t>
            {
                ++attempts;
                return attempts == 1 ? std::nullopt : std::optional<std::size_t>(7);
            },
            [&]()
            {
                ++waits;
            });

    EXPECT_EQ(result, 7U);
    EXPECT_EQ(attempts, 2U);
    EXPECT_EQ(waits, 1U);
}

TEST(Given_SocketIo, When_NonBlockingOperationWouldBlock_Then_ItDoesNotWait)
{
    std::size_t attempts = 0;
    std::size_t waits = 0;

    const std::optional<std::size_t> result =
        tailgate::linux_frontend::impl::detail::CompleteSocketIo<std::size_t>(
            true,
            [&]() -> std::optional<std::size_t>
            {
                ++attempts;
                return std::nullopt;
            },
            [&]()
            {
                ++waits;
            });

    EXPECT_FALSE(result.has_value());
    EXPECT_EQ(attempts, 1U);
    EXPECT_EQ(waits, 0U);
}
