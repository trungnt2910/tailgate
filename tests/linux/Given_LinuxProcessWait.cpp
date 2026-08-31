#include <chrono>

#include <sys/wait.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "ProcessWait.h"

TEST(Given_LinuxProcessWait, When_ProcessExits_Then_ExitNotificationIsDelivered)
{
    const pid_t processId = fork();
    if (processId == 0)
    {
        _exit(0);
    }

    const bool exited = processId > 0 && tailgate::linux_frontend::WaitForProcessExit(
                                             processId, std::chrono::seconds(1));
    if (processId > 0)
    {
        (void)waitpid(processId, nullptr, 0);
    }

    EXPECT_GT(processId, 0);
    EXPECT_TRUE(exited);
}
