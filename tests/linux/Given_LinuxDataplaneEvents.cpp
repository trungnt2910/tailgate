#include "LinuxDataplaneEvents.h"

#include <gtest/gtest.h>

#include <chrono>
#include <poll.h>
#include <thread>

using namespace std::chrono_literals;

TEST(Given_DeadlineTimer, When_DeadlinePasses_Then_DescriptorBecomesReadable)
{
    tailgate::linux_frontend::UniqueFd timer =
        tailgate::linux_frontend::CreateDeadlineTimerFd(20ms);
    EXPECT_GE(timer.Fd, 0);
    pollfd descriptor{.fd = timer.Fd, .events = POLLIN, .revents = 0};

    const int ready = poll(&descriptor, 1, 500);

    EXPECT_EQ(ready, 1);
    EXPECT_NE(descriptor.revents & POLLIN, 0);
}

TEST(Given_DeadlineTimer, When_Reset_Then_OriginalDeadlineDoesNotFire)
{
    tailgate::linux_frontend::UniqueFd timer =
        tailgate::linux_frontend::CreateDeadlineTimerFd(100ms);
    EXPECT_GE(timer.Fd, 0);
    std::this_thread::sleep_for(60ms);
    tailgate::linux_frontend::ResetDeadlineTimerFd(timer.Fd, 200ms);
    pollfd descriptor{.fd = timer.Fd, .events = POLLIN, .revents = 0};

    const int ready = poll(&descriptor, 1, 80);

    EXPECT_EQ(ready, 0);
    EXPECT_EQ(descriptor.revents, 0);
}
