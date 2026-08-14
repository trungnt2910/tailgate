#include <gtest/gtest.h>

#include <tailgate/base/Clock.h>

#include "bg/DI.h"

TEST(Given_UwpBackgroundBindings, When_ResolvingCoreClock_Then_ProductionGraphIsComplete)
{
    auto injector = tailgate::uwp::bg::CreateRs2PluginInjector();

    tailgate::base::IClock& clock = injector.create<tailgate::base::IClock&>();
    const auto now = clock.Now();

    EXPECT_NE(now, tailgate::base::IClock::TimePoint{});
}
