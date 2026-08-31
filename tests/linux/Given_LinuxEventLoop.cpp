#include <chrono>
#include <memory>
#include <optional>

#include <unistd.h>

#include <gtest/gtest.h>

#include <tailgate/base/EventLoop.h>

#include "UniqueFd.h"
#include "event/EventRegistry.h"
#include "impl/EventLoop.h"
#include "impl/TimeProvider.h"

namespace
{

constexpr tailgate::base::EventToken TestToken{.Value = 42};
constexpr std::size_t MaximumEvents = 4;

} // namespace

TEST(Given_LinuxEventLoop, When_DescriptorBecomesReadable_Then_TokenIsReturned)
{
    int descriptors[2]{};
    ASSERT_EQ(pipe(descriptors), 0);
    tailgate::linux_frontend::UniqueFd readDescriptor(descriptors[0]);
    tailgate::linux_frontend::UniqueFd writeDescriptor(descriptors[1]);
    auto registry = std::make_shared<tailgate::linux_frontend::event::EventRegistry>();
    tailgate::linux_frontend::impl::EventLoop loop(registry);
    tailgate::linux_frontend::event::EventHandle handle = registry->Register(
        readDescriptor.Fd, tailgate::linux_frontend::event::EventInterest::Readable, TestToken);
    constexpr std::uint8_t Byte = 1;
    ASSERT_EQ(write(writeDescriptor.Fd, &Byte, sizeof(Byte)), sizeof(Byte));

    const tailgate::base::EventWaitResult result = loop.Wait(MaximumEvents);

    ASSERT_EQ(result.Events.size(), 1U);
    EXPECT_EQ(result.Status, tailgate::base::EventWaitStatus::Events);
    EXPECT_EQ(result.Events.front().Token, TestToken);
    EXPECT_TRUE(tailgate::base::HasReadiness(result.Events.front().Readiness,
                                             tailgate::base::EventReadiness::Readable));
}

TEST(Given_LinuxEventLoop, When_DeadlinePasses_Then_WaitReturnsWithoutPolling)
{
    auto registry = std::make_shared<tailgate::linux_frontend::event::EventRegistry>();
    tailgate::linux_frontend::impl::EventLoop loop(registry);
    tailgate::linux_frontend::impl::TimeProvider timeProvider;
    std::unique_ptr<tailgate::base::WaitToken> deadline =
        timeProvider.After(std::chrono::milliseconds(20));

    const tailgate::base::EventWaitResult result = loop.Wait(*deadline, MaximumEvents);

    EXPECT_EQ(result.Status, tailgate::base::EventWaitStatus::DeadlineReached);
    EXPECT_TRUE(result.Events.empty());
}

TEST(Given_LinuxEventLoop, When_Woken_Then_BlockingWaitReturnsWakeStatus)
{
    auto registry = std::make_shared<tailgate::linux_frontend::event::EventRegistry>();
    tailgate::linux_frontend::impl::EventLoop loop(registry);
    loop.Wake();

    const tailgate::base::EventWaitResult result = loop.Wait(MaximumEvents);

    EXPECT_EQ(result.Status, tailgate::base::EventWaitStatus::Woken);
    EXPECT_TRUE(result.Events.empty());
}
