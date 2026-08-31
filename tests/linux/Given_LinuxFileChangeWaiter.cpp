#include <chrono>
#include <filesystem>

#include <gtest/gtest.h>

#include "FileChangeWaiter.h"
#include "State.h"

#include "LinuxTestEnvironment.h"

TEST(Given_LinuxFileChangeWaiter, When_StatusIsReplaced_Then_ChangeIsDelivered)
{
    tailgate::test::LinuxTestHome home("linux-file-change-waiter");
    std::filesystem::create_directories(tailgate::linux_frontend::StateDirectory());
    tailgate::linux_frontend::FileChangeWaiter waiter(tailgate::linux_frontend::StateDirectory());
    tailgate::linux_frontend::DaemonStatus status;
    status.ProcessId = 42;

    tailgate::linux_frontend::WriteDaemonStatus(status);
    const bool changed = waiter.WaitForChange(tailgate::linux_frontend::DaemonStatusFileName,
                                              std::chrono::seconds(1));

    EXPECT_TRUE(changed);
}
