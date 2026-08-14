#include <memory>

#include <gtest/gtest.h>

#include <tailgate/PlatformFrontend.h>

TEST(Given_LinuxBindings, When_CreatingFrontend_Then_ProductionGraphIsComplete)
{
    std::unique_ptr<tailgate::platform::IPlatformFrontend> frontend =
        tailgate::platform::CreateFrontend();

    const bool created = frontend != nullptr;

    EXPECT_TRUE(created);
}
