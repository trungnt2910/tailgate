#include <chrono>
#include <future>
#include <thread>

#include <gtest/gtest.h>

#include "Lifecycle.h"

TEST(Given_Lifecycle, When_StopIsRequestedDuringWait_Then_WaitCompletesPromptly)
{
    tailgate::linux_frontend::Lifecycle::ClearStop();
    tailgate::linux_frontend::Lifecycle::ClearReload();
    tailgate::linux_frontend::Lifecycle::Initialize();
    std::promise<void> entered;
    std::promise<bool> completed;
    std::future<void> enteredFuture = entered.get_future();
    std::future<bool> completedFuture = completed.get_future();
    std::jthread waiter(
        [&]()
        {
            entered.set_value();
            completed.set_value(
                tailgate::linux_frontend::Lifecycle::WaitForChange(std::chrono::hours(1)));
        });
    enteredFuture.wait();

    tailgate::linux_frontend::Lifecycle::RequestStop();
    const std::future_status status = completedFuture.wait_for(std::chrono::seconds(1));
    const bool retry = status == std::future_status::ready ? completedFuture.get() : true;
    tailgate::linux_frontend::Lifecycle::ClearStop();

    EXPECT_EQ(status, std::future_status::ready);
    EXPECT_FALSE(retry);
}
